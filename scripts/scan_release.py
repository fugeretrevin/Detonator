"""Build the release archive and prove it carries no secrets, before it is shared.

`CLAUDE.md` requires the public artifact to be produced with `git archive` and never by zipping
the working directory - zipping ignores `.gitignore` and ships `.env`, `.git/` and `.venv/`.
That rule has been broken on this project once already: a live `.env` left the machine inside a
folder ZIP, which is the origin of the Modal token rotation item (W10). An independent audit in
November 2026 received another folder ZIP containing `.env`, `.git` and `.venv`, so the rule
needs a check that runs rather than a paragraph that is remembered.

This script does both halves: it builds the archive from a named commit, then scans **entry
names and file bytes**. It exits non-zero on any finding, so it can gate a release.

Usage:
    python scripts/scan_release.py                      # build from HEAD into a temp file, scan
    python scripts/scan_release.py --commit v1.0        # a specific commit or tag
    python scripts/scan_release.py --archive out.zip    # scan an archive that already exists
    python scripts/scan_release.py --keep out.zip       # build, scan, and keep the artifact
    python scripts/scan_release.py --extra-patterns p.txt

`--extra-patterns` takes a file of one regex per line, for identifiers that must not appear but
must not be committed either - specifically the embargoed package name and address from the
November 2 disclosure, which `docs/HANDOFF.md` section 4 keeps out of this repository. Keep that
file outside the repo (or in an ignored path) and pass it at release time.

Deliberately **not** silenced: this prints every finding with its file and a short excerpt. A
false positive is documented and reviewed, never suppressed by broadening a rule.
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

# Published on purpose: without it nobody can verify the committed behavior records. Its
# absence is also a failure (see REQUIRED_ENTRIES) because three tests and the SBOM demo
# depend on it - an audit extraction that dropped it produced three spurious test failures.
PUBLIC_KEY = "eval/sbom/public_key.pem"
REQUIRED_ENTRIES = (PUBLIC_KEY,)

# Committed on purpose and required by CLAUDE.md to stay current. It holds variable *names*
# with placeholder values, which is the opposite of a secret, so it is exempt from the
# `.env` name rule rather than from the content rules - a real value pasted into it is still
# caught by those.
NAME_ALLOWED = {".env.example"}

# Entry-name rules. Anything matching is a hard failure wherever it appears in the archive.
NAME_RULES: tuple[tuple[str, str], ...] = (
    (r"(^|/)\.env($|\.)", "environment file (may hold live secrets)"),
    (r"(^|/)\.git/", "git directory (history, remotes, possibly credentials)"),
    (r"(^|/)\.venv/", "virtualenv (vendored binaries and local config)"),
    (r"(^|/)node_modules/", "installed dependencies do not belong in a source release"),
    (r"(^|/)\.aws/|(^|/)\.ssh/|(^|/)\.npmrc$", "credential file"),
    (r"\.(key|p12|pfx|jks|keystore)$", "private key material"),
    (r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$", "ssh private key"),
)

# Content rules. Lengths are deliberate: real tokens are long, and this repository's tests
# legitimately contain short fakes such as `ghs_SECRET` and `ghs_x`. Matching on realistic
# length keeps those out of the report without the rule having to know about test files, so a
# real token pasted into a test would still be caught.
CONTENT_RULES: tuple[tuple[str, str], ...] = (
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "private key block"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "GitHub token"),
    (r"\bgithub_pat_[A-Za-z0-9_]{60,}\b", "GitHub fine-grained PAT"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id"),
    (r"\bASIA[0-9A-Z]{16}\b", "AWS temporary access key id"),
    (r"\bsk-[A-Za-z0-9]{32,}\b", "OpenAI-style API key"),
    (r"\b(?:ak|as)-[A-Za-z0-9]{22,}\b", "Modal token id/secret"),
    (r"\bxox[abpsr]-[A-Za-z0-9-]{20,}\b", "Slack token"),
    (r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.", "JWT"),
)

# Only the public key may carry a PEM body. Any other PEM is a failure even if it claims to be
# public, because "it is only a public key" is exactly the assumption that ships a private one.
PEM_ALLOWED = {PUBLIC_KEY}

TEXT_SUFFIXES = {
    ".py", ".md", ".txt", ".json", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".sh", ".bash",
    ".js", ".ts", ".html", ".css", ".pem", ".env", ".example", ".service", ".conf", ".lock",
}  # fmt: skip
MAX_SCAN_BYTES = 4 * 1024 * 1024

# Documentation and private ranges that are correct to ship: RFC 5737 examples, the sandbox's
# own fixed addresses, loopback. A public address outside these is reported for review rather
# than failed, because the Chamber's address is already in the docs on purpose.
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAX_IP_NOTES = 12
IP_ALLOWED_PREFIXES = (
    "192.0.2.", "198.51.100.", "203.0.113.",  # RFC 5737 documentation
    "10.", "172.16.", "192.168.", "127.", "0.", "169.254.", "255.",
)  # fmt: skip


@dataclass(frozen=True)
class Finding:
    entry: str
    rule: str
    detail: str
    fatal: bool = True

    def __str__(self) -> str:
        mark = "FAIL" if self.fatal else "note"
        return f"  [{mark}] {self.entry}: {self.rule}\n         {self.detail}"


def build_archive(commit: str, out: Path) -> None:
    """`git archive` includes only tracked files, which is the entire point."""
    subprocess.run(
        ["git", "archive", "--format=zip", "-o", str(out), commit],
        check=True, capture_output=True,
    )  # fmt: skip


def _excerpt(text: str, match: re.Match) -> str:
    """Enough context to judge a finding, never the whole secret."""
    start = max(0, match.start() - 24)
    shown = text[start : match.start()] + "<<<" + match.group(0)[:12] + "...>>>"
    return " ".join(shown.split())[-100:]


def _is_textual(name: str) -> bool:
    return Path(name).suffix.lower() in TEXT_SUFFIXES or "/" not in name and "." not in name


def _matches_path(name: str, allowed: str) -> bool:
    """`git archive` adds no prefix by default, but tolerate one built with `--prefix`."""
    return name == allowed or name.endswith("/" + allowed)


def decoy_values(name: str, text: str) -> set[str]:
    """The fake per-run canaries a recorded detonation legitimately contains.

    `chamber/decoys.py::make_decoys` mints values shaped like real credentials on purpose, so
    that a payload's own regex accepts them - `ghp_` + 36 random chars, `AKIA` + 16. They are
    `secrets.choice` output that never authenticated to anything, and recorded fixtures of real
    runs carry one run's worth under a `decoys` key.

    Resolved by parsing the JSON and collecting only values under a `decoys` object, so a real
    token elsewhere in the same fixture is still reported. Documented as a known false positive
    rather than silenced by loosening a credential rule.
    """
    if not name.endswith(".json"):
        return set()
    try:
        data = json.loads(text)
    except ValueError:
        return set()
    found: set[str] = set()

    def walk(node: object, in_decoys: bool) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, in_decoys or key == "decoys")
        elif isinstance(node, list):
            for value in node:
                walk(value, in_decoys)
        elif isinstance(node, str) and in_decoys:
            found.add(node)

    walk(data, False)
    return found


def scan_archive(path: Path, extra_patterns: list[tuple[str, str]] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    rules = [(re.compile(p), why) for p, why in CONTENT_RULES]
    rules += [(re.compile(p), f"extra pattern: {why}") for p, why in (extra_patterns or [])]
    seen_ips: dict[str, str] = {}

    with zipfile.ZipFile(path) as zf:
        names = [i.filename for i in zf.infolist() if not i.is_dir()]

        for name in names:
            exempt_name = any(_matches_path(name, a) for a in NAME_ALLOWED)
            for pattern, why in NAME_RULES:
                if re.search(pattern, name) and not exempt_name:
                    findings.append(Finding(name, "disallowed path", why))
            pem_ok = any(_matches_path(name, a) for a in PEM_ALLOWED)
            if name.endswith(".pem") and not pem_ok:
                findings.append(
                    Finding(name, "unexpected .pem", f"only {PUBLIC_KEY} may ship as a .pem")
                )
            if not _is_textual(name):
                continue
            try:
                raw = zf.read(name)
            except KeyError:  # pragma: no cover - defensive
                continue
            if len(raw) > MAX_SCAN_BYTES:
                findings.append(
                    Finding(name, "not scanned", f"{len(raw)} bytes exceeds the scan limit", False)
                )
                continue
            text = raw.decode("utf-8", errors="replace")
            known_fake = decoy_values(name, text)
            for pattern, why in rules:
                hits = [m for m in pattern.finditer(text) if m.group(0) not in known_fake]
                if not hits:
                    continue
                if why == "private key block" and pem_ok:
                    continue
                findings.append(Finding(name, why, _excerpt(text, hits[0])))
            for ip in IP_RE.findall(text):
                if not ip.startswith(IP_ALLOWED_PREFIXES) and ip not in seen_ips:
                    seen_ips[ip] = name

        for required in REQUIRED_ENTRIES:
            if not any(_matches_path(n, required) for n in names):
                findings.append(
                    Finding(
                        required,
                        "required file missing",
                        "signed behavior records cannot be verified without it, and three "
                        "tests fail when it is absent",
                    )
                )

    shown = sorted(seen_ips.items())[:MAX_IP_NOTES]
    findings += [
        Finding(where, "public IP address (review, not a failure)", ip, False)
        for ip, where in shown
    ]
    if len(seen_ips) > MAX_IP_NOTES:
        findings.append(
            Finding(
                "(summary)",
                "public IP addresses (review, not a failure)",
                f"{len(seen_ips)} distinct addresses in total; {MAX_IP_NOTES} listed above. "
                "Recorded detonation telemetry legitimately contains the hosts packages "
                "contacted.",
                False,
            )
        )
    return findings


def load_extra_patterns(path: Path) -> list[tuple[str, str]]:
    out = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if line and not line.startswith("#"):
            out.append((line, f"line {i} of {path.name}"))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--commit", default="HEAD", help="commit-ish to archive (default HEAD)")
    ap.add_argument("--archive", type=Path, help="scan this archive instead of building one")
    ap.add_argument("--keep", type=Path, help="build to this path and keep it")
    ap.add_argument("--extra-patterns", type=Path, help="file of extra regexes, one per line")
    args = ap.parse_args(argv)

    extra = load_extra_patterns(args.extra_patterns) if args.extra_patterns else []
    if args.extra_patterns and not extra:
        print(f"warning: {args.extra_patterns} contained no patterns", file=sys.stderr)
    if not args.extra_patterns:
        print(
            "note: no --extra-patterns given, so the embargoed disclosure identifiers were NOT\n"
            "      checked. See this script's docstring before sharing the artifact.\n"
        )

    tmp: tempfile.TemporaryDirectory | None = None
    if args.archive:
        archive = args.archive
    else:
        if args.keep:
            archive = args.keep
        else:
            tmp = tempfile.TemporaryDirectory()
            archive = Path(tmp.name) / "release.zip"
        build_archive(args.commit, archive)
        print(f"built {archive} from {args.commit}")

    try:
        findings = scan_archive(archive, extra)
    finally:
        if tmp is not None:
            tmp.cleanup()

    fatal = [f for f in findings if f.fatal]
    notes = [f for f in findings if not f.fatal]
    if notes:
        print(f"\n{len(notes)} item(s) for review:")
        for f in notes:
            print(f)
    if fatal:
        print(f"\n{len(fatal)} BLOCKING finding(s):")
        for f in fatal:
            print(f)
        print("\nDo not share this artifact.")
        return 1
    print("\nNo blocking findings. Entry names and file bytes both scanned.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
