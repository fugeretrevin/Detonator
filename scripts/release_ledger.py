"""Print the release ledger: exactly which code, model and measurements a claim refers to.

A recurring problem on this project is that "it is in the repo", "it is deployed" and "it is
what the numbers were measured on" are three different things, and the write-up has to be
precise about which it means. An independent audit in November 2026 put it directly: *a
repository feature should never be described as live just because it passed local tests.*

So this collects the identifiers in one place. Everything it prints is read from the working
tree - no cloud calls, no credentials, no paid APIs - and the fields it *cannot* know locally
are printed as explicit TODO lines with the command that answers them, rather than guessed or
silently omitted.

    python scripts/release_ledger.py              # human-readable
    python scripts/release_ledger.py --markdown   # a table to paste into a doc

Owner-only fields (deployed Brain version, Chamber code SHA, sandbox image digest) need the
Modal and EC2 consoles. `--modal` will run `scripts/modal_cli.py app history` to fill the Brain
row, and is **off by default** precisely because it authenticates as the owner.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _git(*args: str) -> str:
    try:
        out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=30)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - defensive
        return ""


def git_facts() -> dict[str, str]:
    dirty = _git("status", "--porcelain")
    ahead = _git("rev-list", "--count", "origin/main..HEAD")
    return {
        "Commit (HEAD)": _git("rev-parse", "HEAD") or "unknown",
        "Short SHA": _git("rev-parse", "--short", "HEAD") or "unknown",
        "Branch": _git("rev-parse", "--abbrev-ref", "HEAD") or "unknown",
        "Commit date": _git("log", "-1", "--format=%ci") or "unknown",
        "Describes as": _git("describe", "--tags", "--always", "--dirty") or "unknown",
        "Working tree": "DIRTY — commit before releasing" if dirty else "clean",
        "Unpushed commits": ahead or "unknown (no origin/main?)",
    }


def contract_version() -> str:
    text = (ROOT / "shared" / "contract.py").read_text(encoding="utf-8")
    m = re.search(r"^CONTRACT_VERSION\s*=\s*(\d+)", text, re.M)
    return m.group(1) if m else "unknown"


def eval_facts() -> dict[str, str]:
    path = ROOT / "eval" / "results.json"
    if not path.exists():
        return {"Evaluation": "eval/results.json missing"}
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("rows", [])
    kinds: dict[str, int] = {}
    for r in rows:
        kinds[r.get("kind", "?")] = kinds.get(r.get("kind", "?"), 0) + 1
    cohorts = ", ".join(f"{k} {n}" for k, n in sorted(kinds.items()))
    stamped = data.get("commit") or "unknown"
    head = _git("rev-parse", "--short", "HEAD")
    drift = ""
    if stamped != "unknown" and head and not head.startswith(stamped[: len(head)]):
        # Only code changes matter; docs and generated results do not move the numbers.
        changed = _git("diff", "--name-only", f"{stamped}..HEAD")
        code = [
            f for f in changed.splitlines()
            if f.startswith(("brain/", "chamber/", "shared/", "eval/cases.py"))
        ]  # fmt: skip
        if code:
            # Naming the files is the point: it prompts the check, it does not conclude it. A
            # comment-only edit to brain/rules.py lands here and changes no number.
            drift = f" — REVIEW whether these changed behaviour: {', '.join(code)}"
        else:
            drift = " — no code changed since (docs/tests only)"
    return {
        "Evaluation stamped at": f"{stamped}{drift}",
        "Evaluation scored at": data.get("scored_at") or "unknown",
        "Evaluation cases": f"{len(rows)} ({cohorts})",
        "Contract version": contract_version(),
    }


def sbom_facts() -> dict[str, str]:
    path = ROOT / "eval" / "sbom" / "index.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:  # pragma: no cover - defensive
        return {}
    commit = data.get("detector_commit") if isinstance(data, dict) else None
    return {"Signed SBOM records built at": commit or "unknown"}


def model_facts() -> dict[str, str]:
    path = ROOT / "eval" / "results.json"
    models: set[str] = set()
    if path.exists():
        text = path.read_text(encoding="utf-8")
        models = set(re.findall(r"muse-[\w.-]+|llama-[\w.-]+", text, re.I))
    summary = ROOT / "eval" / "results.md"
    md = summary.read_text(encoding="utf-8") if summary.exists() else ""
    if m := re.search(r"with\s+([\w.-]+muse[\w.-]*|muse[\w.-]+)", md):
        models.add(m.group(1))
    return {"Model(s) in the stamped eval": ", ".join(sorted(models)) or "unknown"}


# Fields no local command can answer, with the command that does.
_SSH = "ssh to the Chamber, then: "
OWNER_FIELDS: tuple[tuple[str, str], ...] = (
    ("Brain deployed version", "python scripts/modal_cli.py app history pr-detonator"),
    ("Chamber code SHA on the box", _SSH + "git -C /opt/pr-detonator rev-parse HEAD"),
    (
        "Sandbox image digest",
        _SSH + "docker image inspect --format '{{index .RepoDigests 0}}' detonator-sandbox:latest",
    ),
    ("Chamber address persistence", "AWS console: is the Chamber IP Elastic or ephemeral? (W6)"),
    ("Demo video URL", "paste into docs/SUBMISSION.md, then confirm it plays signed out (W1)"),
    ("Demo PR head SHAs", "the exact SHAs the recorded check runs belong to"),
    ("Modal token rotated", "owner confirms; do before any deploy (W10)"),
    ("AMI snapshot id", "AWS console (W6)"),
    ("SBOM signing key backed up", "owner confirms, off this machine and out of the repo"),
)


def modal_version() -> str:
    """Only called with --modal: this authenticates as the owner."""
    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "modal_cli.py"), "app", "history", "pr-detonator"],
        cwd=ROOT, capture_output=True, text=True, timeout=180,
    )  # fmt: skip
    for line in (out.stdout or "").splitlines():
        if m := re.search(r"\bv(\d+)\b.*?(\d{4}-\d{2}-\d{2} \d{2}:\d{2})", line):
            return f"v{m.group(1)} deployed {m.group(2)}"
    return "could not parse `app history` output"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Print the release ledger.")
    ap.add_argument("--markdown", action="store_true", help="emit a markdown table")
    ap.add_argument(
        "--modal", action="store_true",
        help="query the deployed Brain version (authenticates as the owner)",
    )  # fmt: skip
    args = ap.parse_args(argv)

    known: dict[str, str] = {}
    known.update(git_facts())
    known.update(eval_facts())
    known.update(model_facts())
    known.update(sbom_facts())

    todo = list(OWNER_FIELDS)
    if args.modal:
        known["Brain deployed version"] = modal_version()
        todo = [(k, v) for k, v in todo if k != "Brain deployed version"]

    if args.markdown:
        print("| Field | Value |\n|---|---|")
        for k, v in known.items():
            print(f"| {k} | `{v}` |")
        for k, cmd in todo:
            print(f"| {k} | **TODO** — `{cmd}` |")
    else:
        width = max(len(k) for k in list(known) + [k for k, _ in todo])
        print("RELEASE LEDGER — collected from the working tree\n")
        for k, v in known.items():
            print(f"  {k.ljust(width)}  {v}")
        print("\nNeeds the owner (not knowable from the repository):\n")
        for k, cmd in todo:
            print(f"  {k.ljust(width)}  TODO")
            print(f"  {' '.ljust(width)}    -> {cmd}")
        print(
            "\nReminder: a feature present in this commit is not necessarily deployed."
            "\nSee docs/HANDOFF.md sections 5b and 5c for the current divergence."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
