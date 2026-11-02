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
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from brain.rules import is_external
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
) -> dict:
    """The observed-behavior record for one exact package version."""
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
    return {
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


def _main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "verify":
        record = json.loads(Path(argv[1]).read_text())
        ok = verify(record, Path(argv[2]).read_bytes())
        name = f"{record.get('package')}@{record.get('version')}"
        print(f"{'OK  ' if ok else 'FAIL'} {name}  sha256={digest(record)}")
        return 0 if ok else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
