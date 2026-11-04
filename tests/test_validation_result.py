"""`eval/VALIDATION_RESULT.md` must match the scored W12 comparison in validation_result.json.

The headline — 7/7 attacks blocked, 0 dangerous misses, 12/14 agreement with the cold agent's
frozen labels — is pinned to its artifact, and the honest caveats (not a human audit, small n)
must stay in the writeup.
"""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "eval" / "validation_result.json"
DOC = ROOT / "eval" / "VALIDATION_RESULT.md"


@pytest.fixture(scope="module")
def result() -> dict:
    if not RESULT.exists():  # pragma: no cover - committed
        pytest.skip("validation_result.json not present")
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_no_attack_was_let_through(result):
    """The one number that must hold: every case the agent labelled Blocked, the tool blocked."""
    assert result["summary"]["dangerous_misses"] == 0
    assert result["summary"]["attacks_blocked"] == result["summary"]["attacks_total"] == 7


def test_the_agreement_count_matches_the_doc(result):
    exact = result["summary"]["exact_match"]
    total = result["summary"]["total"]
    text = " ".join(DOC.read_text(encoding="utf-8").split())
    assert f"{exact} / {total}" in text or f"{exact}/{total}" in text


def test_the_labels_were_frozen_before_scoring(result):
    """Every tool verdict in the result must correspond to a pre-registered label, and the
    labels file must still say it was written blind."""
    labels = json.loads((ROOT / "eval" / "validation_labels.json").read_text(encoding="utf-8"))
    label_ids = set(labels["cases"])
    result_ids = {r["id"] for r in result["rows"]}
    assert result_ids == label_ids, result_ids ^ label_ids
    for r in result["rows"]:
        assert r["label"] == labels["cases"][r["id"]]["expected"], r["id"]


def test_the_writeup_keeps_the_honesty_caveats():
    text = " ".join(DOC.read_text(encoding="utf-8").split()).lower()
    assert "not a human third-party" in text or "not a human audit" in text
    assert "scored by us" in text
    assert "14 cases is small" in text or "not quoted as" in text


def test_the_two_disagreements_are_benign_not_misses(result):
    """Both non-matches are on benign cases and in a safe direction: v02 could-not-verify
    (sandbox limit), v06 clean-vs-needs-review (lenient on a benign). Neither is an attack."""
    non_match = [r for r in result["rows"] if r["cat"] != "match"]
    assert len(non_match) == 2
    for r in non_match:
        assert r["label"] != "Blocked", f"{r['id']} disagreement is on an attack case"
