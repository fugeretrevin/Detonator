"""`eval.band_sim` - recovering W2 round 2 from recorded trials instead of new API calls.

W2 ships best-of-N sampling **off** because the round-2 re-run was abandoned when the provider
throttled, leaving acceptance 1 (attack flip rate 0) and acceptance 3 (benign Blocked stays 0)
unmeasured for the widened band. This module reconstructs the band from the two arms already
recorded in `eval/REPEAT_W2.json`, and the tests here pin both what that establishes and - more
importantly - what it does not.

The honest split it produced:
  acceptance 1  0/38 simulated flips, plus a *proof* of the safety direction (monotonicity)
  acceptance 2  0 of the 4 benign cases present moved in the stricter direction
  acceptance 3  UNMEASURABLE from this corpus: all 6 at-risk packages are absent from it
  acceptance 4  already priced and passing (W2 round 2)

So the verdict stays `MODEL_SAMPLES = 1`, and a test below asserts that, because the gate
requires all four on a measured run and one is still missing.
"""

import json

import pytest

from brain.sampling import BORDERLINE_TITLES
from eval.band_sim import (
    AT_RISK_BENIGN,
    DATA,
    MERGEABLE,
    band_outcomes,
    load,
    report,
)


@pytest.fixture(scope="module")
def data() -> dict:
    if not DATA.exists():  # pragma: no cover - committed
        pytest.skip("eval/REPEAT_W2.json not present")
    return load()


# --- the reconstruction itself ---


def test_a_borderline_single_sample_is_replaced_by_the_resampled_arm():
    row = {"outcomes": {"full": ["Needs review"], "sampled": ["Blocked"]}}
    assert band_outcomes(row) == ["Blocked"]


def test_a_non_borderline_single_sample_is_kept_unchanged():
    """Blocked cannot be improved on - `combine` takes a max - and Clean is excluded from the
    band deliberately, so neither triggers a second call."""
    for verdict in ("Blocked", "Clean"):
        row = {"outcomes": {"full": [verdict], "sampled": ["Blocked"]}}
        assert band_outcomes(row) == [verdict]


def test_both_borderline_titles_trigger_resampling():
    """ "Could not verify" is in the band for a measured reason: `gm08`'s install timed out, so
    `verified` is permanently False and it can never be titled "Needs review". The first
    version of the band silently excluded it and all 7 unverified cases."""
    assert set(BORDERLINE_TITLES) == {"Needs review", "Could not verify"}
    for title in BORDERLINE_TITLES:
        row = {"outcomes": {"full": [title], "sampled": ["Blocked"]}}
        assert band_outcomes(row) == ["Blocked"]


def test_mismatched_arm_lengths_are_an_error_not_a_silent_truncation():
    """`zip(strict=True)`: pairing trial 1 of one arm with trial 2 of another would quietly
    invent a result."""
    row = {"outcomes": {"full": ["Clean", "Clean"], "sampled": ["Blocked"]}}
    with pytest.raises(ValueError):
        band_outcomes(row)


# --- what the recorded data shows ---


def test_the_band_removes_the_m12_flip_that_motivated_all_of_w2(data):
    row = next(r for r in data["rows"] if r["id"] == "m12-domain-exfil")
    full, band = row["outcomes"]["full"], band_outcomes(row)
    assert len(set(full)) > 1, "m12 is the case W2 exists for; it should flip at N=1"
    assert set(band) == {"Blocked"}, "the band should settle it"


def test_no_attack_flips_under_the_reconstructed_band(data):
    attacks = [r for r in data["rows"] if r["kind"] != "benign"]
    assert len(attacks) == 38
    flipped = [r["id"] for r in attacks if len(set(band_outcomes(r))) > 1]
    assert flipped == [], f"simulated flips: {flipped}"


def test_the_band_never_makes_an_attack_more_mergeable_than_n_equals_one(data):
    """Monotonicity, checked against the data as well as argued. The band either keeps the
    single sample's verdict or raises it, so a mergeable band outcome implies the N=1 outcome
    was mergeable too - never the reverse."""
    for row in data["rows"]:
        if row["kind"] == "benign":
            continue
        for full, band in zip(row["outcomes"]["full"], band_outcomes(row), strict=True):
            if band in MERGEABLE:
                assert full in MERGEABLE, (
                    f"{row['id']}: band {band!r} is mergeable but N=1 was {full!r}"
                )


def test_no_benign_case_present_is_blocked_in_any_trial(data):
    """Acceptance 3's condition, on the 4 benign cases this corpus happens to contain. Not the
    same as acceptance 3 passing - see the next test."""
    benign = [r for r in data["rows"] if r["kind"] == "benign"]
    assert len(benign) == 4
    for row in benign:
        assert "Blocked" not in band_outcomes(row), row["id"]


def test_the_at_risk_packages_were_measured_separately_and_stayed_unblocked():
    """Acceptance 3, closed on Nov 3 by `eval/REPEAT_W2_NATIVE.json`: the 6 packages absent
    from the 42-case corpus, run on their own with the real band code at `8057a42`."""
    path = DATA.parent / "REPEAT_W2_NATIVE.json"
    if not path.exists():  # pragma: no cover - committed
        pytest.skip("eval/REPEAT_W2_NATIVE.json not present")
    native = json.loads(path.read_text(encoding="utf-8"))
    assert native["dirty"] is False, "a dirty stamp makes the run unattributable"
    assert native["arms"] == ["sampled"] and native["trials"] == 5
    ids = {r["id"] for r in native["rows"]}
    assert ids == set(AT_RISK_BENIGN), f"expected the 6 at-risk packages, got {sorted(ids)}"
    for row in native["rows"]:
        outcomes = row["outcomes"]["sampled"]
        assert "Blocked" not in outcomes, f"{row['id']} escalated to Blocked: {outcomes}"
        assert len(set(outcomes)) == 1, f"{row['id']} flipped: {outcomes}"


def test_this_corpus_alone_could_not_have_settled_acceptance_three(data):
    """Why a separate run was needed at all. W2 names the 6 benign "Could not verify"
    native-build packages as the population the widened band puts at risk, and not one of them
    is in this 42-case corpus - so its clean benign column said nothing about the condition
    that mattered. The previous version of this test was named as though acceptance 3 were
    unsettleable; it is settled, just not from here (see the test above)."""
    present = {r["id"] for r in data["rows"]}
    assert not (set(AT_RISK_BENIGN) & present), (
        "an at-risk package is now in this corpus; the separate run may be redundant - re-check"
    )


def test_the_corpus_is_the_stamped_one_and_carries_both_arms(data):
    assert data["arms"] == ["full", "sampled"] or set(data["arms"]) == {"full", "sampled"}
    assert data["trials"] == 5
    assert data["dirty"] is False, "a dirty tree makes the recorded arms unattributable"
    assert len(data["rows"]) == 42


# --- the conclusion this does and does not license ---


def test_sampling_is_still_off_in_production():
    """The gate requires all four acceptance conditions on a measured run. Three are satisfied
    and one is not, so the default must not have moved. If someone flips this, the simulation
    was mistaken for the measurement."""
    from brain.sampling import MODEL_SAMPLES

    assert MODEL_SAMPLES == 1


def test_the_report_runs_and_states_both_arms_and_the_band(data, capsys):
    report()
    out = capsys.readouterr().out
    assert "full (N=1, recorded)" in out
    assert "sampled (worst of 3, recorded)" in out
    assert "band (reconstructed)" in out
    assert "CANNOT be settled" in out, "the limitation has to be in the output, not just here"


def test_the_module_spends_no_money():
    """The whole point: W2 round 2 was lost to a throttled paid run. This reads a committed
    file."""
    source = DATA.parent.joinpath("band_sim.py").read_text(encoding="utf-8")
    for forbidden in ("import modal", "LlmClient", "api_key", "httpx", "requests"):
        assert forbidden not in source, f"band_sim references {forbidden}"


def test_the_recorded_arms_are_not_identical(data):
    """If `full` and `sampled` were the same column, the reconstruction would be vacuous."""
    differing = [r["id"] for r in data["rows"] if r["outcomes"]["full"] != r["outcomes"]["sampled"]]
    assert differing, "the two arms are identical; the simulation would prove nothing"


def test_the_simulation_is_described_as_an_estimate_not_a_measurement():
    """Five trials cannot distinguish a flip rate of 0 from a few percent, and the two arms
    were independent runs rather than the same draws. The module must say so."""
    source = DATA.parent.joinpath("band_sim.py").read_text(encoding="utf-8")
    text = " ".join(source.split())
    assert "Monte Carlo estimate" in text
    assert "not a replay of the band itself" in text
    assert "evidence, not the measured run" in text


def test_every_case_in_the_corpus_is_reconstructable(data):
    """No row may be skipped: a missing arm would make the band undefined for it."""
    for row in data["rows"]:
        assert set(row["outcomes"]) >= {"full", "sampled"}, row["id"]
        assert len(band_outcomes(row)) == data["trials"], row["id"]


def test_the_data_file_is_valid_json_and_committed():
    assert DATA.exists()
    json.loads(DATA.read_text(encoding="utf-8"))
