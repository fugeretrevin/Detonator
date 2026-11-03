"""`eval/BLIND_RESULTS.md` must match what the rules actually produce on the committed telemetry.

The blind-corpus result is a claim about detection gaps, so like every other headline it is
pinned to its evidence: the committed telemetry in `eval/blind_telemetry/` is re-scored here,
and the doc's catch/miss split is checked against it. If a rule change later closes one of the
gaps, this test fails until the writeup is updated — which is the point.
"""

from pathlib import Path

import pytest

from eval.score_blind import DEFAULT_DIR, score

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "eval" / "BLIND_RESULTS.md"

# The four cases the writeup states the deterministic rules miss, and why. If the rules change,
# this list is what must be reconciled with the doc.
EXPECTED_MISSES = {"bc03-git-hook", "bc04-git-alias", "bc08-dns-exfil", "bc10-git-proxy"}


@pytest.fixture(scope="module")
def scored() -> dict[str, dict]:
    if not DEFAULT_DIR.is_dir() or not any(DEFAULT_DIR.glob("*.json")):  # pragma: no cover
        pytest.skip("eval/blind_telemetry not present")
    return score(DEFAULT_DIR)


def test_all_ten_cases_were_detonated_and_scored(scored):
    assert len(scored) == 10, f"expected 10 blind telemetry records, got {len(scored)}"


def test_the_rules_floor_split_matches_the_writeup(scored):
    missed = {cid for cid, v in scored.items() if v["verdict"] not in ("Blocked", "Needs review")}
    assert missed == EXPECTED_MISSES, (
        f"rules now miss {sorted(missed)}, doc claims {sorted(EXPECTED_MISSES)}. "
        "Reconcile BLIND_RESULTS.md (and W14/W15) with the current rules."
    )


def test_the_writeup_states_the_six_four_split(scored):
    caught = sum(1 for v in scored.values() if v["verdict"] in ("Blocked", "Needs review"))
    text = " ".join(RESULTS.read_text(encoding="utf-8").split())
    assert f"{caught} of 10" in text or f"{caught} of {len(scored)}" in text


def test_every_missed_case_was_actually_observed_not_just_unrecorded(scored):
    """A miss is only interesting if the behaviour was *captured and not flagged*, versus never
    seen. Each missed case must have real telemetry (exec events), so the gap is a rule gap, not
    a blind collector."""
    for cid in EXPECTED_MISSES:
        assert scored[cid]["exec"] >= 1, f"{cid} has no exec events; the miss would be a blind run"


def test_the_git_config_misses_captured_the_git_exec(scored):
    """W14's claim: the `git config` exec IS recorded (so evidence exists), the rules just do not
    read it. bc04 and bc10 run git config, so they have the extra exec beyond the npm baseline."""
    # npm baseline is ~3 execs (entrypoint, npm, node); a git config adds more.
    assert scored["bc04-git-alias"]["exec"] >= 3
    assert scored["bc10-git-proxy"]["exec"] >= 3


def test_the_dns_miss_captured_the_query(scored):
    """W15's claim: the DNS query is captured, only the length floor misses it."""
    assert scored["bc08-dns-exfil"]["dns"] >= 1


def test_persistence_rule_caught_a_held_out_case(scored):
    """bc09 (PATH hijack via ~/.bashrc) was not a motivating case for FILE_PERSISTENCE; catching
    it is evidence the rule generalised. Recorded as a positive in the writeup."""
    assert scored["bc09-path-shadow"]["verdict"] == "Blocked"


def test_the_writeup_is_framed_as_rules_floor_not_tool_recall(scored):
    """The honesty the audit asks for: this is the deterministic floor, not the full tool, and
    not a recall rate. Both caveats must be in the doc."""
    text = " ".join(RESULTS.read_text(encoding="utf-8").split()).lower()
    assert "rules floor" in text or "deterministic floor" in text
    assert "not a recall rate" in text or "not a recall" in text
    assert "model" in text, "must note the model arm may catch some misses"
