"""Registry-scale sweep: detonate packages published to npm minutes ago (HARDENING_PLAN #2).

The curated benign set in cases.py is packages *we* chose. This instead takes whatever npm
published most recently and detonates it, so the false-positive number comes from real-world
traffic nobody curated — and the behavior atlas fills with real data.

  python -m eval.registry_sweep manifest 100 manifest_sweep.json sweep_names.json
  # on the Chamber:  run_chamber.py manifest_sweep.json <repo> <sha> out/
  python -m eval.registry_sweep score out/ sweep_names.json eval/SWEEP.md

This runs arbitrary, unreviewed third-party code. The sandbox is the containment: no tokens
or host environment, no cloud role, TCP-only egress with exfil services sinkholed, one job at
a time, killed on timeout. Nothing discovered here is ever copied into this repository, and a
package is only ever described by the behavior we recorded — never accused.
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import quote

import httpx
import truststore

truststore.inject_into_ssl()  # local machine only: Norton re-signs TLS

CHANGES = "https://replicate.npmjs.com/_changes"
REGISTRY = "https://registry.npmjs.org"
BASE_COMMAND = ["npm", "install", "--no-audit", "--no-fund"]
# npm allows these; we still refuse anything that could confuse a shell or a path.
SAFE_NAME = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$")
TIMEOUT_S = 120


def _id_for(name: str) -> str:
    return "pkg-" + name.replace("@", "").replace("/", "-").replace(".", "-")


def fetch_recent(count: int, http: httpx.Client) -> list[dict]:
    """Most recently published packages that still resolve, with a little metadata."""
    seen: list[str] = []
    resp = http.get(CHANGES, params={"descending": "true", "limit": count * 3})
    resp.raise_for_status()
    for row in resp.json().get("results", []):
        name = str(row.get("id") or "")
        if SAFE_NAME.match(name) and name not in seen:
            seen.append(name)

    out: list[dict] = []
    for name in seen:
        if len(out) >= count:
            break
        try:
            doc = http.get(f"{REGISTRY}/{quote(name, safe='@')}", timeout=15.0)
            if doc.status_code != 200:
                continue  # unpublished or deleted between the feed and now
            body = doc.json()
            latest = (body.get("dist-tags") or {}).get("latest")
            version = (body.get("versions") or {}).get(latest or "") or {}
            if not latest:
                continue
            scripts = sorted(
                s
                for s in (version.get("scripts") or {})
                if s in {"preinstall", "install", "postinstall", "prepare"}
            )
            out.append({
                "name": name,
                "version": latest,
                "declares_install_scripts": scripts,
                "first_published": (body.get("time") or {}).get("created"),
            })  # fmt: skip
        except (httpx.HTTPError, ValueError):
            continue
    return out


def write_manifest(count: int, manifest_path: Path, names_path: Path) -> None:
    http = httpx.Client(timeout=30.0, follow_redirects=True)
    packages = fetch_recent(count, http)
    manifest = [
        {"id": _id_for(p["name"]), "command": [*BASE_COMMAND, f"{p['name']}@{p['version']}"],
         "timeout_s": TIMEOUT_S}
        for p in packages
    ]  # fmt: skip
    manifest_path.write_text(json.dumps(manifest, indent=1))
    names_path.write_text(json.dumps({_id_for(p["name"]): p for p in packages}, indent=1))
    declared = sum(1 for p in packages if p["declares_install_scripts"])
    print(f"{len(packages)} packages; {declared} declare install scripts -> {manifest_path}")


# --- scoring (rules only: deterministic, no model cost across a large sweep) ---


def score(results_dir: Path, names_path: Path) -> dict:
    from brain.enrich import enrich_connects, github_meta_cidrs
    from brain.rules import DEFAULT_ALLOWED_DOMAINS, Severity, domain_allowed, evaluate, is_external
    from brain.verdict import unverified_reason
    from shared.contract import DetonateResult

    names = json.loads(names_path.read_text())
    cidrs = github_meta_cidrs()
    rows, atlas = [], {}
    for pkg_id, meta in names.items():
        path = results_dir / f"{pkg_id}.json"
        if not path.exists():
            continue
        result = enrich_connects(DetonateResult.model_validate_json(path.read_text()))
        hits = evaluate(result, allowed_cidrs=cidrs)
        level = max((h.severity for h in hits), default=Severity.NONE)
        # Same predicate as the production check: a failed install, truncated telemetry or a
        # blind sensor is "Could not verify", never "Clean". Previously an install that exited
        # nonzero still scored Clean here, which inflated the clean count.
        reason = unverified_reason(result)
        verdict = ("Blocked" if level >= Severity.HIGH else
                   "Could not verify" if reason else
                   "Needs review" if level == Severity.LOW else "Clean")  # fmt: skip
        ran = sorted({s.package for s in result.executed_scripts if s.package})
        hosts = sorted(
            {c.resolved_domain or c.daddr for c in result.connect_events if is_external(c.daddr)}
        )
        offreg = [h for h in hosts if not domain_allowed(h, DEFAULT_ALLOWED_DOMAINS)]
        rows.append({
            "package": f"{meta['name']}@{meta['version']}",
            "verdict": verdict,
            "rules": sorted({h.rule_id for h in hits}),
            "declared_install_scripts": meta["declares_install_scripts"],
            "ran_install_scripts": bool(result.executed_scripts),
            "hosts": hosts,
            "off_registry_hosts": offreg,
            "status": result.status,
            "exit_code": result.exit_code,
            "duration_s": result.duration_s,
            "unverified_reason": reason,
        })  # fmt: skip
        for p in ran:
            if p.startswith("."):
                continue  # node_modules/.bin is a directory, not a package
            atlas.setdefault(p, set()).update(hosts)
    return {"rows": rows, "atlas": {k: sorted(v) for k, v in atlas.items()}}


def report(data: dict) -> str:
    rows = data["rows"]
    n = len(rows)
    # A package that refused to install exercised nothing, so it must not pad the "clean"
    # count. The change feed is full of per-platform binaries (darwin/win32/arm64 variants)
    # that cannot install on the linux-x64 sandbox.
    installed = [r for r in rows if r["status"] == "completed" and not r["exit_code"]]
    skipped = [r for r in rows if r not in installed]
    verdicts = Counter(r["verdict"] for r in installed)
    m = len(installed)
    ran = [r for r in installed if r["ran_install_scripts"]]
    offreg = [r for r in installed if r["off_registry_hosts"]]
    lines = [
        "# Registry sweep: packages published to npm minutes before we ran them",
        "",
        f"{n} packages taken straight from npm's change feed and detonated, newest first. "
        "Nobody curated this list — it is whatever the registry published. Scored with the "
        "deterministic rules only (no model calls), so a sweep this size costs VM time alone.",
        "",
        f"**{len(skipped)} of the {n} never installed** on this platform and are excluded from "
        "the rates below: the feed is largely per-platform binary subpackages "
        "(`…-darwin-arm64`, `…-windows-amd64`) that npm refuses on linux-x64, plus one whose "
        f"version had already been unpublished. Everything else is scored over the **{m} "
        "packages that actually installed**.",
        "",
        "Those excluded runs are recorded as **Could not verify**, never Clean: an install that "
        "exited nonzero, timed out, lost telemetry to the event cap, or produced no process "
        "events at all is an absence of evidence, not a clean bill of health. That is a "
        "usability limit of this sandbox, not a judgement about the package.",
        "",
        "| Result | Count |",
        "|---|---|",
    ]
    for v in ("Clean", "Needs review", "Blocked", "Could not verify"):
        lines.append(f"| {v} | {verdicts.get(v, 0)}/{m} |")
    lines += [
        "",
        f"- **{len(ran)}/{m} ran install scripts.**",
        f"- **{len(offreg)}/{m} contacted a host outside the npm registry and GitHub.**",
        "",
    ]
    # Findings are reported across *all* rows, including ones that timed out: an install that
    # hangs after reaching a hardcoded address is exactly the case worth looking at.
    findings = [r for r in rows if r["rules"] or r["off_registry_hosts"]]
    if findings:
        header = "| Package | Verdict | Rules | Off-registry hosts | Install |"
        lines += [f"## Findings (across all {n}, including ones that did not finish)", "",
                  header, "|---|---|---|---|---|"]  # fmt: skip
        for r in findings:
            state = r["status"] if r["status"] != "completed" else f"exit {r['exit_code']}"
            lines.append(
                f"| `{r['package']}` | {r['verdict']} | {' '.join(r['rules']) or '-'} "
                f"| {', '.join(r['off_registry_hosts']) or '-'} | {state} |"
            )
        lines += ["", "These are **observations, not accusations.** A package fetching its own "
                  "vendor CDN at install is ordinary, and one automated run is not evidence of "
                  "intent. Anything here would need human review before any claim is made about "
                  "it.", ""]  # fmt: skip
    if data["atlas"]:
        lines += ["## Behavior atlas (real packages, real install behavior)", "",
                  "| Package | Hosts contacted at install |", "|---|---|"]  # fmt: skip
        for pkg, hosts in sorted(data["atlas"].items()):
            lines.append(f"| `{pkg}` | {', '.join(hosts) or '—'} |")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> None:
    if argv[0] == "manifest":
        write_manifest(int(argv[1]), Path(argv[2]), Path(argv[3]))
    elif argv[0] == "score":
        data = score(Path(argv[1]), Path(argv[2]))
        out = Path(argv[3])
        out.write_text(report(data), encoding="utf-8")
        out.with_suffix(".json").write_text(json.dumps(data, indent=1))
        print(report(data)[:1500])
    else:
        raise SystemExit("usage: manifest <n> <manifest> <names> | score <dir> <names> <out.md>")


if __name__ == "__main__":
    main(sys.argv[1:])
