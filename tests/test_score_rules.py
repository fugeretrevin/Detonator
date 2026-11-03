"""`eval.score_rules` - the offline harness that justifies rule changes.

This tool decides whether a new rule ships, so it has to be harder to fool than the rules
themselves. Two properties matter most, and both are tested here:

1. **It reproduces a known answer.** Its `--verify` mode re-scores the rules arm from recorded
   telemetry and compares against the column already stamped in `eval/results.json`. Run live
   against the 142-case v3 telemetry it reported 142/142 agreement before any rule change, and
   141 agree + 1 recorded drift after. If it could not reproduce the committed result, nothing
   it said about a *change* would be worth anything.

2. **Its drift list cannot hide a regression.** `KNOWN_DRIFT` is strict both ways: an
   unexplained disagreement fails, and so does an entry that no longer disagrees.

The telemetry itself is not committed (see `docs/HANDOFF.md` section 6), so these tests use the
committed real fixtures and synthetic score dicts rather than the full corpus.
"""

import json

import pytest

from eval import score_rules
from shared.contract import DetonateResult

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

FIXTURES = __import__("pathlib").Path(__file__).parent / "fixtures"


def real(name: str) -> DetonateResult:
    return DetonateResult.model_validate_json(
        (FIXTURES / f"detonate_real_{name}.json").read_text(encoding="utf-8")
    )


# --- scoring ---


@pytest.mark.parametrize(
    "name,expected",
    [
        ("r01", "Blocked"),
        ("r02", "Blocked"),
        ("e4", "Blocked"),
        ("e5", "Blocked"),
        ("dep", "Blocked"),
        ("re2", "Clean"),
    ],  # fmt: skip
)
def test_scoring_the_real_fixtures_matches_their_known_rules_verdict(name, expected):
    assert score_rules.score(real(name))["verdict"] == expected


def test_the_absent_model_is_reported_as_absent_not_as_approval():
    """`combine` must be handed an outcome meaning "the model did not run". If it were handed
    a *benign* verdict instead, the rules arm would silently become "rules + a model that
    always approves", and every unverified case would read Clean."""
    assert score_rules.NO_MODEL.skipped is True
    assert score_rules.NO_MODEL.verdict is None
    assert score_rules.NO_MODEL.error


def test_an_unverifiable_run_does_not_score_clean():
    """Fail-closed still applies: a timed-out install is Could not verify, never Clean."""
    res = real("re2").model_copy(update={"status": "timeout", "exit_code": None})
    assert score_rules.score(res)["verdict"] == "Could not verify"


def test_scoring_reports_the_rules_that_fired_so_a_diff_can_name_them():
    row = score_rules.score(real("r02"))
    assert "NET_EXFIL_SERVICE" in row["rules"] and "CRED_FILE_ACCESS" in row["rules"]
    assert row["rules"] == sorted(row["rules"]), "sorted, so a diff is stable"


def test_unreadable_records_are_skipped_rather_than_aborting_the_run(tmp_path):
    (tmp_path / "good.json").write_text(
        (FIXTURES / "detonate_real_dep.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "wrong-shape.json").write_text('{"hello": 1}', encoding="utf-8")
    loaded = score_rules.load(tmp_path)
    assert set(loaded) == {"good"}


# --- verify: reproducing the stamped column, and the strictness of the drift list ---


def _stub_stamp(monkeypatch, stamped: dict[str, str]) -> None:
    monkeypatch.setattr(score_rules, "stamped_rules_arm", lambda: stamped)
    monkeypatch.setattr(score_rules, "kinds", lambda: dict.fromkeys(stamped, "benign"))


def test_verify_passes_when_every_case_agrees(monkeypatch, capsys):
    _stub_stamp(monkeypatch, {"a": "Clean", "b": "Blocked"})
    monkeypatch.setattr(score_rules, "KNOWN_DRIFT", {})
    scored = {"a": {"verdict": "Clean", "rules": []}, "b": {"verdict": "Blocked", "rules": ["X"]}}
    assert score_rules.verify(scored) == 0
    assert "2 of 2 agree" in capsys.readouterr().out


def test_verify_fails_on_an_unexplained_disagreement(monkeypatch, capsys):
    _stub_stamp(monkeypatch, {"a": "Clean"})
    monkeypatch.setattr(score_rules, "KNOWN_DRIFT", {})
    assert score_rules.verify({"a": {"verdict": "Blocked", "rules": ["X"]}}) == 1
    assert "MISMATCH a" in capsys.readouterr().out


def test_verify_accepts_a_disagreement_that_is_recorded_with_its_reason(monkeypatch, capsys):
    _stub_stamp(monkeypatch, {"a": "Clean"})
    monkeypatch.setattr(
        score_rules, "KNOWN_DRIFT", {"a": ("Clean", "Blocked", "a rule was added; 0 benign FP")}
    )
    assert score_rules.verify({"a": {"verdict": "Blocked", "rules": ["X"]}}) == 0
    out = capsys.readouterr().out
    assert "known drift a: Clean -> Blocked" in out
    assert "0 benign FP" in out, "the reason must be printed, not just the fact"


def test_verify_rejects_a_drift_entry_whose_direction_does_not_match(monkeypatch):
    """A drift entry licenses one specific change, not any change to that case."""
    _stub_stamp(monkeypatch, {"a": "Clean"})
    monkeypatch.setattr(score_rules, "KNOWN_DRIFT", {"a": ("Clean", "Needs review", "why")})
    assert score_rules.verify({"a": {"verdict": "Blocked", "rules": ["X"]}}) == 1


def test_verify_rejects_a_stale_drift_entry(monkeypatch, capsys):
    """If a case agrees with the stamp again, the entry is obsolete and must go - otherwise
    the list accumulates permanent exemptions nobody rechecks."""
    _stub_stamp(monkeypatch, {"a": "Clean"})
    monkeypatch.setattr(score_rules, "KNOWN_DRIFT", {"a": ("Clean", "Blocked", "why")})
    assert score_rules.verify({"a": {"verdict": "Clean", "rules": []}}) == 1
    assert "STALE KNOWN_DRIFT" in capsys.readouterr().out


def test_every_recorded_drift_entry_explains_itself():
    """Shipped-state check on the real list: a bare "known difference" with no measurement is
    exactly the hand-wave this project does not accept."""
    for case, (was, now, why) in score_rules.KNOWN_DRIFT.items():
        assert was and now and was != now, case
        assert len(why) > 60, f"{case}: the reason is too thin to audit"
        assert any(w in why.lower() for w in ("measured", "benign", "uncurated")), (
            f"{case}: the reason should say what was measured"
        )


def test_the_recorded_drift_is_the_cron_rule_and_nothing_else():
    """Pins the current state: one intentional difference from the stamp. If a second appears
    without a re-score, that is worth noticing."""
    assert set(score_rules.KNOWN_DRIFT) == {"gm05-cron-inject"}
    assert score_rules.KNOWN_DRIFT["gm05-cron-inject"][:2] == ("Clean", "Blocked")


# --- compare: what a change moved ---


def test_compare_reports_no_change_when_nothing_moved(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(score_rules, "kinds", lambda: {"a": "benign"})
    scored = {"a": {"verdict": "Clean", "rules": []}}
    base = tmp_path / "b.json"
    base.write_text(json.dumps(scored), encoding="utf-8")
    assert score_rules.compare(scored, base) == 0
    assert "No change" in capsys.readouterr().out


def test_compare_fails_loudly_when_a_benign_package_becomes_blocked(tmp_path, monkeypatch, capsys):
    """The one outcome that must never pass quietly."""
    monkeypatch.setattr(score_rules, "kinds", lambda: {"pkg": "benign"})
    base = tmp_path / "b.json"
    base.write_text(json.dumps({"pkg": {"verdict": "Clean", "rules": []}}), encoding="utf-8")
    after = {"pkg": {"verdict": "Blocked", "rules": ["NEW_RULE"]}}
    assert score_rules.compare(after, base) == 1
    out = capsys.readouterr().out
    assert "BENIGN NOW BLOCKED" in out and "NEW_RULE" in out


def test_compare_accepts_a_new_attack_catch(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(score_rules, "kinds", lambda: {"atk": "redteam"})
    base = tmp_path / "b.json"
    base.write_text(json.dumps({"atk": {"verdict": "Clean", "rules": []}}), encoding="utf-8")
    after = {"atk": {"verdict": "Blocked", "rules": ["EXEC_SCHEDULED_PERSISTENCE"]}}
    assert score_rules.compare(after, base) == 0
    out = capsys.readouterr().out
    assert "Clean -> Blocked" in out and "No benign package is hard-blocked" in out


def test_compare_names_the_rules_gained_and_lost(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(score_rules, "kinds", lambda: {"x": "malicious"})
    base = tmp_path / "b.json"
    base.write_text(json.dumps({"x": {"verdict": "Blocked", "rules": ["OLD"]}}), encoding="utf-8")
    after = {"x": {"verdict": "Blocked", "rules": ["NEW"]}}
    score_rules.compare(after, base)
    out = capsys.readouterr().out
    assert "+ NEW" in out and "- OLD" in out


# --- the CLI contract ---


def test_a_missing_directory_is_an_error_not_a_crash(tmp_path):
    assert score_rules.main([str(tmp_path / "nope")]) == 2


def test_an_empty_directory_is_an_error(tmp_path):
    assert score_rules.main([str(tmp_path)]) == 2


def test_the_harness_makes_no_network_or_modal_call(monkeypatch):
    """The point of this module is that it is free and offline. `eval/run_brain.py` imports
    modal at module scope; this must not, or it stops working on a fresh clone without the
    Modal SDK."""
    source = __import__("pathlib").Path(score_rules.__file__).read_text(encoding="utf-8")
    for forbidden in ("import modal", "httpx", "requests", "api_key", "LlmClient"):
        assert forbidden not in source, f"score_rules references {forbidden}"
