"""`eval.egress_allowlist` - the offline blast-radius measurement for W8.

The headline claim this module supports is that a curated egress allowlist would not have
affected any benign package in a held-out corpus. That claim rests on two things worth
testing separately: the set arithmetic (cheap to get subtly wrong) and the claim itself,
asserted against the committed sweep data rather than a remembered number.
"""

import pytest

from eval.egress_allowlist import (
    REFUSED,
    TIERS,
    at_risk,
    host_frequency,
    installed_cleanly,
    package_name,
    report,
    rows,
)


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("lodash@4.17.21", "lodash"),
        ("@babel/core@7.0.0", "@babel/core"),
        ("left-pad", "left-pad"),
        ("@scope/pkg", "@scope/pkg"),  # scoped, no version: the `@` at index 0 is not a split
        ("@opencode/cli-darwin-arm64@1.2.3", "@opencode/cli-darwin-arm64"),
    ],
)
def test_package_name_strips_only_the_version(spec, expected):
    assert package_name(spec) == expected


# --- set arithmetic -----------------------------------------------------------------------


def test_a_package_within_the_allowlist_is_not_at_risk():
    corpus = [{"package": "p@1", "hosts": ["registry.npmjs.org"]}]
    assert at_risk(corpus, {"registry.npmjs.org"}) == []


def test_at_risk_reports_only_the_hosts_outside_the_allowlist():
    corpus = [{"package": "p@1", "hosts": ["registry.npmjs.org", "evil.test", "other.test"]}]
    ((row, blocked),) = at_risk(corpus, {"registry.npmjs.org"})
    assert row["package"] == "p@1"
    assert blocked == ["evil.test", "other.test"]  # sorted, and the allowed host excluded


def test_a_package_that_contacted_nothing_is_not_at_risk():
    """`hosts` is absent on rows from an install that never resolved anything."""
    assert at_risk([{"package": "p@1"}], {"registry.npmjs.org"}) == []


def test_host_frequency_counts_packages_not_connections():
    corpus = [
        {"hosts": ["a.test", "a.test", "b.test"]},  # a dedup upstream should make this moot
        {"hosts": ["a.test"]},
    ]
    freq = host_frequency(corpus)
    assert freq["b.test"] == 1 and freq["a.test"] >= 2


@pytest.mark.parametrize(
    "row,expected",
    [
        ({"exit_code": 0, "status": "completed"}, True),
        ({"exit_code": 1, "status": "completed"}, False),
        ({"exit_code": 0, "status": "timeout"}, False),
        ({}, False),
    ],
)
def test_installed_cleanly_requires_both_a_zero_exit_and_a_finished_run(row, expected):
    assert installed_cleanly(row) is expected


# --- the allowlist itself -----------------------------------------------------------------


def test_the_refused_hosts_are_in_no_tier():
    """The refusals are the whole reason this is an allowlist rather than an observation log.
    Adding one to a tier would silently undo that."""
    for tier_name, allowed in TIERS:
        for host in REFUSED:
            assert host not in allowed, f"{host} must not be in {tier_name}"


def test_the_tiers_are_cumulative():
    # strict=False is deliberate: TIERS[1:] is one shorter, which is what pairs them up.
    for (_, narrower), (_, wider) in zip(TIERS, TIERS[1:], strict=False):
        assert narrower < wider, "each tier must strictly contain the one before it"


# --- the claim, against the committed corpora ---------------------------------------------


def test_no_benign_held_out_package_would_be_cut_off_by_the_fitted_allowlist():
    """The W8 finding, asserted rather than recalled: fit on the 500-package sweep, score the
    100-package one, and every package the allowlist would have blocked must be one the
    detector already calls out - not a benign install we would have broken."""
    big, small = rows("SWEEP500.json"), rows("SWEEP.json")
    big_names = {package_name(r["package"]) for r in big}
    held_out = [r for r in small if package_name(r["package"]) not in big_names]
    assert len(held_out) > 50, "too much overlap for this to be a held-out test"

    fitted = set(host_frequency(big)) - set(REFUSED)
    for row, blocked in at_risk(held_out, fitted):
        assert row.get("verdict") == "Blocked", (
            f"{row['package']} is not Blocked but would lose {blocked}: "
            "that is a benign install the allowlist would break"
        )


def test_every_package_in_the_sweep_reached_the_registry():
    """The premise of allowlisting at all: there is one host every install needs. If some
    package installed without touching the registry, the telemetry is incomplete."""
    big = rows("SWEEP500.json")
    assert host_frequency(big)["registry.npmjs.org"] == len(big)


def test_the_report_renders_and_keeps_the_embargoed_identifiers_redacted():
    """docs/HANDOFF.md section 4 keeps the disclosed package's name and address out of this
    repo. The sweep data stores them redacted; the report must not reconstruct them."""
    text = report()
    assert "# Egress allowlist" in text and "Held-out check" in text
    assert "<withheld pending disclosure>" in text  # redaction carried through, not resolved
