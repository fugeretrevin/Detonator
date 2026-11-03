"""`scripts.scan_release` - the gate on what leaves the machine.

A release scanner that reports "clean" is worthless until it is shown to fail on bad input, so
most of this file feeds it archives that *must* be rejected. The rule it exists to enforce is in
`CLAUDE.md`: build the artifact with `git archive`, never by zipping the working directory. That
rule has already been broken once on this project (a live `.env` left the machine inside a folder
ZIP, which is why W10 exists), and an independent audit in November 2026 received another folder
ZIP containing `.env`, `.git` and `.venv`.

The subtle requirement is the last test: recorded detonation fixtures legitimately contain values
shaped exactly like real credentials, because `chamber/decoys.py` mints them that way so a
payload's own regex accepts them. Those must not be reported, while a real token in the same file
must be. Resolving that by file path would have defeated the scanner on the one file most likely
to leak.
"""

import json
import zipfile
from pathlib import Path

import pytest

from scripts.scan_release import PUBLIC_KEY, scan_archive

# Shaped like the real thing and long enough to clear the length floors in CONTENT_RULES.
REAL_LOOKING_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
REAL_LOOKING_AWS = "AKIA" + "QRSTUVWX01234567"
PRIVATE_KEY_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"
)


def archive(tmp_path: Path, entries: dict[str, str], include_key: bool = True) -> Path:
    """A zip shaped like `git archive` output. The public key is present unless a test is
    specifically checking that its absence is caught."""
    path = tmp_path / "release.zip"
    if include_key:
        entries = {PUBLIC_KEY: "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
                   **entries}  # fmt: skip
    with zipfile.ZipFile(path, "w") as zf:
        for name, text in entries.items():
            zf.writestr(name, text)
    return path


def fatal(findings) -> list:
    return [f for f in findings if f.fatal]


def test_an_archive_of_only_the_public_key_has_no_blocking_findings(tmp_path):
    assert fatal(scan_archive(archive(tmp_path, {"README.md": "# hello\n"}))) == []


# --- paths that must never ship -----------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        ".env",
        "Detonator/.env",
        ".env.local",
        ".git/config",
        "Detonator/.git/HEAD",
        ".venv/pyvenv.cfg",
        "node_modules/left-pad/index.js",
        ".ssh/id_rsa",
        ".npmrc",
        "deploy.key",
        "id_ed25519",
    ],
)
def test_a_disallowed_path_blocks_the_release(tmp_path, name):
    found = fatal(scan_archive(archive(tmp_path, {name: "whatever"})))
    assert found, f"{name} should have blocked the release"
    assert any(name in f.entry for f in found)


def test_the_env_example_is_allowed_because_claude_md_requires_it(tmp_path):
    """It holds variable names with placeholder values - the opposite of a secret."""
    findings = scan_archive(archive(tmp_path, {".env.example": "GITHUB_APP_ID=\nCHAMBER_URL=\n"}))
    assert fatal(findings) == []


def test_a_real_value_pasted_into_the_env_example_is_still_caught(tmp_path):
    """The name exemption must not become a content exemption."""
    zf = archive(tmp_path, {".env.example": f"TOKEN={REAL_LOOKING_TOKEN}\n"})
    found = fatal(scan_archive(zf))
    assert any("GitHub token" in f.rule for f in found)


# --- credentials in file bytes ------------------------------------------------------------


@pytest.mark.parametrize(
    "content,expected",
    [
        (PRIVATE_KEY_PEM, "private key block"),
        (f"token = {REAL_LOOKING_TOKEN}", "GitHub token"),
        (f"key = {REAL_LOOKING_AWS}", "AWS access key id"),
        ("github_pat_" + "a" * 70, "GitHub fine-grained PAT"),
        ("sk-" + "b" * 40, "OpenAI-style API key"),
        ("ak-" + "c" * 25, "Modal token id/secret"),
    ],
)
def test_a_credential_in_file_bytes_blocks_the_release(tmp_path, content, expected):
    found = fatal(scan_archive(archive(tmp_path, {"notes.md": content})))
    assert any(f.rule == expected for f in found), f"{expected} not reported"


def test_the_short_fakes_this_suite_uses_are_not_reported(tmp_path):
    """`tests/test_detonate_run.py` and others contain `ghs_SECRET`, `ghs_x`, `ghs_read`. The
    length floors in the rules are what keep those quiet, so that the rules never need to know
    which files are tests - a real token in a test file is still caught."""
    text = 'assert "ghs_SECRET" not in out\ntoken = "ghs_x"\nreturn "ghs_read"\n'
    assert fatal(scan_archive(archive(tmp_path, {"tests/test_x.py": text}))) == []


def test_an_excerpt_never_prints_the_whole_secret(tmp_path):
    findings = scan_archive(archive(tmp_path, {"notes.md": f"token = {REAL_LOOKING_TOKEN}"}))
    detail = next(f.detail for f in findings if f.rule == "GitHub token")
    assert REAL_LOOKING_TOKEN not in detail
    assert "..." in detail


# --- the public key: required, and the only PEM allowed -----------------------------------


def test_a_missing_public_key_blocks_the_release(tmp_path):
    """Three tests and the signed-record demo depend on it. An audit extraction that dropped it
    produced three spurious failures, which is what this rule exists to make obvious."""
    found = fatal(scan_archive(archive(tmp_path, {"README.md": "x"}, include_key=False)))
    assert any("required file missing" in f.rule for f in found)


def test_any_other_pem_blocks_the_release(tmp_path):
    found = fatal(scan_archive(archive(tmp_path, {"chamber/tls/server.pem": "whatever"})))
    assert any("unexpected .pem" in f.rule for f in found)


def test_the_allowlist_survives_an_archive_built_with_a_prefix(tmp_path):
    """`git archive --prefix=detonator/` is a legitimate way to build the artifact."""
    entries = {
        f"detonator/{PUBLIC_KEY}": "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
        "detonator/README.md": "# hi",
    }
    assert fatal(scan_archive(archive(tmp_path, entries, include_key=False))) == []


# --- decoys: the one false positive that had to be resolved precisely ----------------------


def test_recorded_decoy_credentials_are_not_reported(tmp_path):
    """`chamber/decoys.py::make_decoys` mints `ghp_` + 36 random chars on purpose, and a
    recorded run's fixture carries them under a `decoys` key. They never authenticated to
    anything."""
    fixture = json.dumps({"job_id": "j", "decoys": {
        "GITHUB_TOKEN": REAL_LOOKING_TOKEN, "AWS_ACCESS_KEY_ID": REAL_LOOKING_AWS,
    }})  # fmt: skip
    assert fatal(scan_archive(archive(tmp_path, {"tests/fixtures/run.json": fixture}))) == []


def test_a_real_token_elsewhere_in_the_same_fixture_is_still_reported(tmp_path):
    """The point of resolving the decoy exemption by JSON position rather than by file path:
    the file most likely to leak must not become exempt wholesale."""
    other = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
    fixture = json.dumps({
        "decoys": {"GITHUB_TOKEN": REAL_LOOKING_TOKEN},
        "stdout_tail": f"npm ERR! using token {other}",
    })  # fmt: skip
    found = fatal(scan_archive(archive(tmp_path, {"tests/fixtures/run.json": fixture})))
    assert any(f.rule == "GitHub token" for f in found), "a non-decoy token must still block"


def test_a_decoy_shaped_value_outside_a_decoys_key_is_reported(tmp_path):
    fixture = json.dumps({"env": {"GITHUB_TOKEN": REAL_LOOKING_TOKEN}})
    found = fatal(scan_archive(archive(tmp_path, {"f.json": fixture})))
    assert any(f.rule == "GitHub token" for f in found)


# --- public IPs are informational, not blocking --------------------------------------------


def test_a_public_ip_is_a_note_not_a_failure(tmp_path):
    """Recorded telemetry legitimately contains the hosts packages contacted."""
    findings = scan_archive(archive(tmp_path, {"t.json": '{"daddr": "104.16.24.34"}'}))
    assert fatal(findings) == []
    assert any("public IP" in f.rule for f in findings)


@pytest.mark.parametrize("ip", ["203.0.113.10", "10.250.0.1", "127.0.0.1", "192.168.1.1"])
def test_documentation_and_private_addresses_are_not_even_noted(tmp_path, ip):
    findings = scan_archive(archive(tmp_path, {"t.json": f'{{"daddr": "{ip}"}}'}))
    assert not any("public IP" in f.rule for f in findings), ip


# --- the real artifact ---------------------------------------------------------------------


def test_the_real_repository_archive_is_clean(tmp_path):
    """The assertion that matters: HEAD, built the approved way, carries nothing blocking.
    Skipped rather than failed where git is unavailable."""
    import shutil
    import subprocess

    if shutil.which("git") is None:
        pytest.skip("git not available")
    out = tmp_path / "head.zip"
    proc = subprocess.run(
        ["git", "archive", "--format=zip", "-o", str(out), "HEAD"],
        capture_output=True, cwd=Path(__file__).resolve().parents[1],
    )  # fmt: skip
    if proc.returncode != 0:
        pytest.skip("not a git work tree")
    found = fatal(scan_archive(out))
    assert found == [], "\n".join(str(f) for f in found)
