"""`eval/CLAIM_LEDGER.md` — every public claim with its evidence, scope and limit.

Proposed by an independent audit so a reader can check any statement without reconstructing the
evidence trail. A ledger is only worth having if it cannot rot, so these tests assert the
properties that would make it misleading rather than merely out of date:

  - every test it names actually exists (a ledger citing a deleted test is worse than no ledger);
  - every artifact it cites is present in the repository;
  - the figures it quotes match the stamped evaluation;
  - the "deliberately not claimed" list is not contradicted by the documents themselves.
"""

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "eval" / "CLAIM_LEDGER.md"


@pytest.fixture(scope="module")
def text() -> str:
    if not LEDGER.exists():  # pragma: no cover - committed
        pytest.skip("eval/CLAIM_LEDGER.md not present")
    return LEDGER.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def collected() -> set[str]:
    """Every test name pytest can actually collect."""
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--collect-only", "--no-header", "tests/"],
        cwd=ROOT, capture_output=True, text=True, timeout=600,
        encoding="utf-8", errors="replace",
    )  # fmt: skip
    names: set[str] = set()
    for line in (out.stdout or "").splitlines():
        if "::" in line:
            node = line.split("::")[-1].strip()
            names.add(node.split("[")[0])
    if not names:  # pragma: no cover - defensive
        pytest.skip("could not collect test names")
    return names


def test_every_test_the_ledger_names_exists(text, collected):
    """A ledger that cites a test which no longer exists is actively misleading: it looks like
    the claim is machine-checked when nothing checks it."""
    named = set(re.findall(r"`(test_[a-z0-9_]+)`", text))
    assert named, "the ledger names no tests; its Test column has stopped meaning anything"
    missing = sorted(n for n in named if n not in collected)
    assert not missing, f"the ledger cites tests that do not exist: {missing}"


def test_every_artifact_the_ledger_cites_exists(text):
    paths = set(re.findall(r"`(eval/[A-Za-z0-9_.]+|brain/[a-z_]+\.py|docs/[A-Z_]+\.md)`", text))
    assert paths
    missing = sorted(p for p in paths if "*" not in p and not (ROOT / p).exists())
    assert not missing, f"the ledger cites missing artifacts: {missing}"


def test_the_quoted_benign_and_attack_figures_match_the_stamp(text):
    rows = json.loads((ROOT / "eval" / "results.json").read_text(encoding="utf-8"))["rows"]
    benign = Counter(r["outcomes"]["full"] for r in rows if r["kind"] == "benign")
    blocked_attacks = sum(
        1 for r in rows if r["kind"] == "malicious" and r["outcomes"]["full"] == "Blocked"
    )
    assert f"0 of {sum(benign.values())} benign controls hard-blocked" in text
    assert f"{blocked_attacks} of {blocked_attacks} designed attacks blocked" in text
    assert benign["Could not verify"] == 6 and "6 of 104 benign unverifiable" in text


def test_the_contract_effect_is_quoted_as_one_case(text):
    """The claim this ledger exists to keep honest: it was published as 5 -> 3 for a day."""
    assert "4 → 3" in text or "4 -> 3" in text
    assert "5 → 3" not in text.split("Published as")[0]


def test_the_sweep_claim_keeps_both_denominators(text):
    assert "73 of 73 that installed" in text
    assert "27" in text and "timed out and is not among the 73" in text


def test_the_not_claimed_list_is_substantive(text):
    """It is the section most likely to be quietly dropped, and the one an audit asked for."""
    section = text.split("deliberately **not** made", 1)
    assert len(section) == 2, "the 'not claimed' section is gone"
    body = section[1]
    for required in ("Zero false positives", "microVM", "event-stream", "Socket",
                     "maintainer fixed", "never hallucinates"):  # fmt: skip
        assert required in body, f"the not-claimed list no longer covers {required!r}"


@pytest.mark.parametrize(
    "forbidden",
    [
        "zero false positives on npm",
        "we catch all supply-chain attacks",
        "blocks all exfiltration",
        "the maintainer fixed",
    ],  # fmt: skip
)
def test_no_public_document_makes_a_disclaimed_claim(forbidden):
    """The ledger disclaims these; the documents must not then make them. Checked outside the
    ledger itself, which necessarily quotes them in order to disclaim them."""
    for rel in ("README.md", "docs/SUBMISSION.md", "demo/DEMO_SCRIPT.md"):
        body = " ".join((ROOT / rel).read_text(encoding="utf-8").split()).lower()
        assert forbidden not in body, f"{rel} makes a claim the ledger disclaims: {forbidden!r}"


def test_every_claim_row_has_a_limit(text):
    """A row without a Limit column entry is the failure mode this document exists to prevent:
    a number with no stated scope."""
    rows = [
        ln for ln in text.splitlines()
        if ln.startswith("| C") or ln.startswith("| M") or ln.startswith("| E")
    ]  # fmt: skip
    assert len(rows) >= 20, f"only {len(rows)} claim rows found; the tables may have moved"
    for row in rows:
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert len(cells) == 6, f"unexpected column count in: {row[:70]}"
        claim_id, _, _, scope, limit, _ = cells
        assert scope, f"{claim_id} has no scope"
        assert len(limit) > 15, f"{claim_id} has no meaningful limit stated: {limit!r}"
