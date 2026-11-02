"""Behavioral SBOM: a per-version record of what a package *does* at install.

A lockfile pins bytes. It tells you nothing about behavior, so a compromised release of a
pinned-by-range dependency passes review. This pins behavior: for one exact
`package@version`, the hosts it contacted, the programs it ran, the install scripts it
executed (each by sha256), and the credential files it opened — captured from the kernel in
a sandbox, not parsed out of source.

Records are canonical JSON (sorted keys, no insignificant whitespace), so the same observed
behavior always produces the same bytes and therefore the same digest. That makes them
diffable across versions ("4.2.1 added a raw-IP connection") and signable: an Ed25519
signature over those bytes lets anyone with the public key check the record wasn't edited.

  python -m brain.sbom verify eval/sbom/<file>.json eval/sbom/public_key.pem
  python -m brain.sbom diff <old>.json <new>.json [public_key.pem]
"""

import base64
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from brain.rules import DEFAULT_ALLOWED_DOMAINS, DROP_DIRS, domain_allowed, is_external
from shared.contract import DetonateResult

SCHEMA = "pr-detonator/behavior-record@1"
SIGNATURE_KEY = "signature"


def build_record(
    package: str,
    version: str,
    result: DetonateResult,
    *,
    detector_commit: str,
    detonated_at: str,
    environment: dict | None = None,
) -> dict:
    """The observed-behavior record for one exact package version. `environment` (sandbox
    image digest, node/npm versions, command) is what makes two records comparable; records
    built without it stay byte-identical to the original schema."""
    hosts = sorted({
        c.resolved_domain or c.daddr
        for c in result.connect_events
        if is_external(c.daddr) and c.protocol == "tcp"
    })  # fmt: skip
    blocked = sorted({
        f"{c.protocol}:{c.daddr}:{c.dport}"
        for c in result.connect_events
        if c.protocol != "tcp"
    })  # fmt: skip
    binaries = sorted({
        e.binary for e in result.exec_events if not e.binary.startswith("/usr/")
    })  # fmt: skip
    scripts = sorted(
        ({"path": s.path, "package": s.package, "sha256": s.sha256}
         for s in result.executed_scripts),
        key=lambda s: s["path"],
    )  # fmt: skip
    extra = {"environment": dict(sorted(environment.items()))} if environment else {}
    return {
        **extra,
        "schema": SCHEMA,
        "package": package,
        "version": version,
        "install": {
            "status": result.status,
            "exit_code": result.exit_code,
            "duration_s": result.duration_s,
            "ran_install_scripts": bool(result.executed_scripts),
        },
        "observed": {
            "hosts": hosts,
            "dns_queries": sorted({q.domain for q in result.dns_queries}),
            "binaries_outside_system_paths": binaries,
            "install_scripts": scripts,
            "credential_files_opened": sorted({f.path for f in result.file_events}),
            "blocked_non_tcp_egress": blocked,
            "telemetry_truncated": result.truncated,
        },
        "provenance": {
            "detonated_at": detonated_at,
            "detector_commit": detector_commit,
            "sandbox": "docker + Tetragon eBPF + logging resolver, egress TCP-only",
        },
    }


def canonical_json(record: dict) -> bytes:
    """Stable bytes for digesting and signing: the signature field itself is excluded."""
    body = {k: v for k, v in record.items() if k != SIGNATURE_KEY}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def digest(record: dict) -> str:
    return hashlib.sha256(canonical_json(record)).hexdigest()


def sign(record: dict, private_key_pem: bytes) -> dict:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("expected an Ed25519 private key")
    sig = key.sign(canonical_json(record))
    return {
        **record,
        SIGNATURE_KEY: {
            "algorithm": "ed25519",
            "sha256": digest(record),
            "value": base64.b64encode(sig).decode(),
        },
    }


def verify(record: dict, public_key_pem: bytes) -> bool:
    """True only if the signature matches these exact bytes and the digest agrees."""
    sig = record.get(SIGNATURE_KEY) or {}
    if sig.get("algorithm") != "ed25519" or not sig.get("value"):
        return False
    if sig.get("sha256") != digest(record):
        return False
    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, Ed25519PublicKey):
        return False
    try:
        key.verify(base64.b64decode(sig["value"]), canonical_json(record))
    except (InvalidSignature, ValueError):
        return False
    return True


def diff_records(old: dict, new: dict) -> dict[str, list[str]]:
    """What changed between two versions of the same package — the registry-watch signal."""
    out: dict[str, list[str]] = {}
    for field in ("hosts", "binaries_outside_system_paths", "credential_files_opened",
                  "dns_queries", "blocked_non_tcp_egress"):  # fmt: skip
        before = set(old.get("observed", {}).get(field) or [])
        after = set(new.get("observed", {}).get(field) or [])
        added, removed = sorted(after - before), sorted(before - after)
        if added:
            out[f"added_{field}"] = added
        if removed:
            out[f"removed_{field}"] = removed
    old_scripts = {s["sha256"] for s in old.get("observed", {}).get("install_scripts") or []}
    new_scripts = {s["sha256"] for s in new.get("observed", {}).get("install_scripts") or []}
    if new_scripts - old_scripts:
        out["changed_install_scripts"] = sorted(new_scripts - old_scripts)
    return out


# --- version delta: what a release changed about install-time behavior ---

# Environment keys that must match for a behavior difference to be attributed to the package.
ENV_KEYS = ("sandbox_image", "node", "npm", "command")


@dataclass(frozen=True)
class BehaviorDelta:
    old: str  # package@version
    new: str
    comparability: str  # comparable | partially_comparable | incomparable
    reasons: list[str]  # why it isn't fully comparable
    changes: dict[str, list[str]]  # diff_records output
    changed_scripts: list[dict]  # {path, old_sha256, new_sha256}; old None = new script
    attention: list[str]  # changes a reviewer should look at first (never a verdict)
    signatures: dict[str, bool | None]  # old/new -> verified, None if no key given

    @property
    def unchanged(self) -> bool:
        return not self.changes and not self.changed_scripts


def _install_ok(record: dict) -> str:
    inst, obs = record.get("install", {}), record.get("observed", {})
    if inst.get("status") != "completed" or inst.get("exit_code"):
        return (
            f"install did not finish cleanly ({inst.get('status')}, exit {inst.get('exit_code')})"
        )
    if obs.get("telemetry_truncated"):
        return "telemetry was truncated"
    return ""


def _comparability(old: dict, new: dict) -> tuple[str, list[str]]:
    hard = [f"{label}: {why}" for label, rec in (("old", old), ("new", new))
            if (why := _install_ok(rec))]  # fmt: skip
    if old.get("package") != new.get("package"):
        hard.append("different packages")
    if hard:
        return "incomparable", hard
    soft = []
    e_old, e_new = old.get("environment"), new.get("environment")
    if not e_old or not e_new:
        soft.append("environment not recorded for both versions (image, node, npm unknown)")
    else:
        soft += [f"{k} differs: {e_old.get(k)} vs {e_new.get(k)}" for k in ENV_KEYS
                 if e_old.get(k) != e_new.get(k)]  # fmt: skip
    c_old = old.get("provenance", {}).get("detector_commit")
    c_new = new.get("provenance", {}).get("detector_commit")
    if c_old != c_new:
        soft.append(f"recorded by different detector versions ({c_old} vs {c_new})")
    return ("partially_comparable" if soft else "comparable"), soft


def _script_key(script: dict) -> str:
    # The same file across versions: package + path inside it (node_modules/<pkg>/...).
    path = script.get("path", "")
    marker = f"node_modules/{script.get('package')}/" if script.get("package") else ""
    return f"{script.get('package')}:{path.split(marker, 1)[-1] if marker else path}"


def _changed_scripts(old: dict, new: dict) -> list[dict]:
    before = {_script_key(s): s for s in old.get("observed", {}).get("install_scripts") or []}
    out = []
    for s in new.get("observed", {}).get("install_scripts") or []:
        prev = before.get(_script_key(s))
        if prev is None or prev.get("sha256") != s.get("sha256"):
            out.append({"path": s.get("path"), "old_sha256": prev and prev.get("sha256"),
                        "new_sha256": s.get("sha256")})  # fmt: skip
    return sorted(out, key=lambda x: x["path"] or "")


def _attention(changes: dict[str, list[str]], scripts: list[dict]) -> list[str]:
    notes = []
    for host in changes.get("added_hosts", []):
        if not domain_allowed(host, DEFAULT_ALLOWED_DOMAINS):
            kind = "raw IP" if host.replace(".", "").isdigit() or ":" in host else "host"
            notes.append(f"new {kind} contacted at install: {host}")
    for b in changes.get("added_binaries_outside_system_paths", []):
        if b.startswith(DROP_DIRS):
            notes.append(f"new program run from a temp/home directory: {b}")
    for f in changes.get("added_credential_files_opened", []):
        notes.append(f"new credential file opened: {f}")
    for e in changes.get("added_blocked_non_tcp_egress", []):
        notes.append(f"new non-TCP egress attempt (blocked): {e}")
    for s in scripts:
        what = "new install script" if s["old_sha256"] is None else "install script changed"
        notes.append(f"{what}: {s['path']}")
    return notes


def behavior_delta(old: dict, new: dict, public_key_pem: bytes | None = None) -> BehaviorDelta:
    """Compare two versions' records. Describes *new behavior*, never maliciousness: a new CDN
    or a rebuilt script is ordinary; the attention list says what to look at first."""
    comparability, reasons = _comparability(old, new)
    changes = diff_records(old, new)
    scripts = _changed_scripts(old, new)
    sigs = {label: (verify(rec, public_key_pem) if public_key_pem else None)
            for label, rec in (("old", old), ("new", new))}  # fmt: skip
    if public_key_pem and not all(sigs.values()):
        comparability = "incomparable"
        reasons = [*reasons, "a record failed signature verification"]
    name = lambda r: f"{r.get('package')}@{r.get('version')}"  # noqa: E731
    return BehaviorDelta(name(old), name(new), comparability, reasons, changes, scripts,
                         _attention(changes, scripts), sigs)  # fmt: skip


def render_delta(d: BehaviorDelta) -> str:
    """Markdown for a reviewer. Record content came from a sandbox running untrusted code, so
    every value is entity-encoded exactly as PR comments are (brain.report.esc)."""
    from brain.report import esc  # report pulls in the whole pipeline; only needed here

    code = lambda s: esc(str(s), 160)  # noqa: E731
    lines = [f"### Install-time behavior: {code(d.old)} → {code(d.new)}", ""]
    sig = {True: "verified", False: "**FAILED**", None: "not checked"}
    lines.append(f"Signatures: old {sig[d.signatures['old']]}, new {sig[d.signatures['new']]}. "
                 "A signature proves the record wasn't edited, not that the package "
                 "is safe.")  # fmt: skip
    why = " — " + "; ".join(code(r) for r in d.reasons) if d.reasons else ""
    lines.append(f"Comparability: **{d.comparability.replace('_', ' ')}**{why}")
    lines.append("")
    if d.comparability == "incomparable":
        return "\n".join([*lines, "Not compared: a difference here would not mean anything."])
    if d.unchanged:
        return "\n".join([*lines, "No change in observed install-time behavior."])
    if d.attention:
        lines += ["**Look at first** (new behavior, not a verdict):", ""]
        lines += [f"- {code(a)}" for a in d.attention]
        lines.append("")
    lines += ["| Change | Values |", "|---|---|"]
    for key, values in d.changes.items():
        if key == "changed_install_scripts":
            continue  # shown per path below
        lines.append(f"| {key.replace('_', ' ')} | {', '.join(code(v) for v in values[:10])} |")
    for s in d.changed_scripts:
        old_sha = (s["old_sha256"] or "none")[:12]
        lines.append(f"| install script {code(s['path'])} | {old_sha} → {s['new_sha256'][:12]} |")
    return "\n".join(lines)


def _main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "verify":
        record = json.loads(Path(argv[1]).read_text())
        ok = verify(record, Path(argv[2]).read_bytes())
        name = f"{record.get('package')}@{record.get('version')}"
        print(f"{'OK  ' if ok else 'FAIL'} {name}  sha256={digest(record)}")
        return 0 if ok else 1
    if len(argv) in (3, 4) and argv[0] == "diff":
        old, new = (json.loads(Path(p).read_text()) for p in argv[1:3])
        key = Path(argv[3]).read_bytes() if len(argv) == 4 else None
        sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to cp1252
        print(render_delta(behavior_delta(old, new, key)))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
