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

# What the CURRENT deterministic rules miss on the blind set. Of the original four, bc04/bc10
# are now caught by EXEC_GIT_CONFIG_PERSIST (W14) and bc08 by the lowered hex-label floor (W15),
# leaving only bc03 (a .git/hooks file write, which needs a Chamber tracing change). If the
# rules change again, this is what must be reconciled with the doc.
EXPECTED_MISSES = {"bc03-git-hook"}
# The misses as first detonated, which the model-arm run (blind_model_arm.json) was scored
# against. Frozen record, so this stays four.
ORIGINAL_MISSES = {"bc03-git-hook", "bc04-git-alias", "bc08-dns-exfil", "bc10-git-proxy"}


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


def test_the_writeup_states_the_current_rules_floor_split(scored):
    caught = sum(1 for v in scored.values() if v["verdict"] in ("Blocked", "Needs review"))
    assert caught == 9, f"current rules floor is {caught}/10; update the doc and this test"
    text = " ".join(RESULTS.read_text(encoding="utf-8").split())
    assert f"{caught} of 10" in text, "the doc must state the current 9/10 rules floor"
    assert "6 of 10" in text, "the doc should still record the original 6/10 before the fixes"


def test_bc03_is_out_of_scope_not_a_detection_gap(scored):
    """The one case the rules do not flag. Investigation (chamber/detonate.py strips `.git`
    before the install) showed its `.git/hooks/` write throws ENOENT and lands nothing: the
    install script ran (exec events exist) but produced no malicious file event, so "Clean" is
    correct — nothing happened. This is a documented scope boundary, not a rule gap."""
    assert EXPECTED_MISSES == {"bc03-git-hook"}
    row = scored["bc03-git-hook"]
    assert row["exec"] >= 1, "the install script ran"
    # No persistence/credential file event landed — only npm's own ~/.npmrc read, which is one
    # file event at most and never a malicious write. The hook write failed silently.
    assert row["verdict"] == "Clean"
    text = " ".join(RESULTS.read_text(encoding="utf-8").split())
    assert "out of scope" in text and "strips" in text, (
        "the doc must explain bc03 is out of scope (the .git strip), not an open gap"
    )


def test_the_git_config_cases_are_now_caught_by_the_rule(scored):
    """W14 partly closed: bc04 and bc10 run `git config`, whose args EXEC_GIT_CONFIG_PERSIST now
    reads. Both should block at the rules floor."""
    assert scored["bc04-git-alias"]["verdict"] == "Blocked"
    assert "EXEC_GIT_CONFIG_PERSIST" in scored["bc04-git-alias"]["rules"]
    assert scored["bc10-git-proxy"]["verdict"] == "Blocked"
    assert "EXEC_GIT_CONFIG_PERSIST" in scored["bc10-git-proxy"]["rules"]


def test_the_dns_case_is_now_caught_by_the_lowered_floor(scored):
    """W15 closed: bc08's 24-char hex label was under the old 40-char floor; the all-hex path
    now trips at 20, so it blocks. The query was always captured — only the threshold missed."""
    assert scored["bc08-dns-exfil"]["dns"] >= 1
    assert scored["bc08-dns-exfil"]["verdict"] == "Blocked"
    assert "DNS_ENCODED_LABEL" in scored["bc08-dns-exfil"]["rules"]


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


# --- the full-pipeline result (model arm on the committed telemetry) ---

MODEL_ARM = ROOT / "eval" / "blind_model_arm.json"


@pytest.fixture(scope="module")
def model_rows() -> dict[str, dict]:
    if not MODEL_ARM.exists():  # pragma: no cover - committed
        pytest.skip("eval/blind_model_arm.json not present")
    import json

    return {r["id"]: r for r in json.loads(MODEL_ARM.read_text(encoding="utf-8"))["rows"]}


def test_the_full_pipeline_flags_every_original_miss(model_rows):
    """The recorded full-pipeline run: each case the rules missed *at first detonation* is
    flagged (Blocked or Needs-review) once the model reads the source."""
    for cid in ORIGINAL_MISSES:
        full = model_rows[cid]["outcomes"]["full"]
        assert full in ("Blocked", "Needs review"), f"{cid} full-pipeline verdict is {full}"


def test_bc10_is_recorded_as_needs_review_not_blocked(model_rows):
    """The one case the writeup must not overstate: bc10 is suspicious -> Needs review, which is
    mergeable under the default policy. Calling it 'blocked' would be false."""
    assert model_rows["bc10-git-proxy"]["outcomes"]["full"] == "Needs review"
    text = " ".join(RESULTS.read_text(encoding="utf-8").split())
    assert "bc10" in text and "Needs review" in text


def test_the_writeup_keeps_the_single_draw_and_no_overblock_caveats():
    text = " ".join(RESULTS.read_text(encoding="utf-8").split()).lower()
    assert "single draw" in text, "the one-call-per-case variance caveat must be stated"
    assert "zero" in text and "104 benign" in text, (
        "the 'not over-blocking' evidence (0/104 benign, from the main eval) must be cited, "
        "since this all-attack set cannot show discrimination on its own"
    )
