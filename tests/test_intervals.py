"""`eval.intervals` - exact binomial bounds for the headline proportions.

Checked against closed forms where they exist, because the first version of the bisection was
silently inverted: it reported a lower bound ABOVE the upper bound for 1/421, and 0.0% lower
bounds for 9/10 and 19/20. The two binomial tails move in opposite directions in p, and the
boundary cases (0/n, n/n) hid the bug because they never reach the bisection at all.
"""

import math

import pytest

from eval.intervals import ALPHA, CLAIMS, clopper_pearson

HALF = ALPHA / 2


@pytest.mark.parametrize("n", [1, 2, 10, 20, 98, 104, 421])
def test_zero_successes_matches_the_closed_form(n):
    lo, hi = clopper_pearson(0, n)
    assert lo == 0.0
    assert hi == pytest.approx(1 - HALF ** (1 / n))


@pytest.mark.parametrize("n", [1, 2, 10, 16, 20, 104])
def test_all_successes_matches_the_closed_form(n):
    lo, hi = clopper_pearson(n, n)
    assert hi == 1.0
    assert lo == pytest.approx(HALF ** (1 / n))


@pytest.mark.parametrize("k,n", [(1, 421), (9, 10), (19, 20), (3, 7), (50, 100), (1, 2)])
def test_the_interval_is_ordered_and_contains_the_point_estimate(k, n):
    """The regression guard for the inverted bisection. `lo <= k/n <= hi` is the whole
    definition of a confidence interval, and the broken version violated both halves."""
    lo, hi = clopper_pearson(k, n)
    assert 0.0 <= lo < hi <= 1.0, f"{k}/{n} gave [{lo}, {hi}]"
    assert lo <= k / n <= hi


@pytest.mark.parametrize("label,k,n,_note", CLAIMS)
def test_every_published_claim_has_a_well_formed_interval(label, k, n, _note):
    lo, hi = clopper_pearson(k, n)
    assert lo <= k / n <= hi, label
    assert lo < hi, label


def test_the_bounds_invert_the_exact_binomial_test():
    """The definition, checked directly: at the lower bound, P(X >= k) is alpha/2; at the
    upper bound, P(X <= k) is alpha/2."""
    k, n = 19, 20
    lo, hi = clopper_pearson(k, n)

    def cdf(kk: int, p: float) -> float:
        return sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(kk + 1))

    assert 1 - cdf(k - 1, lo) == pytest.approx(HALF, abs=1e-9)
    assert cdf(k, hi) == pytest.approx(HALF, abs=1e-9)


def test_known_values_match_the_independent_audit():
    """An outside review computed these; recomputing them here is the check that we did not
    simply copy its arithmetic into the write-up."""
    assert clopper_pearson(0, 104)[1] == pytest.approx(0.0348, abs=5e-4)
    assert clopper_pearson(0, 98)[1] == pytest.approx(0.0369, abs=5e-4)
    assert clopper_pearson(10, 10)[0] == pytest.approx(0.692, abs=5e-3)
    lo, hi = clopper_pearson(19, 20)
    assert lo == pytest.approx(0.751, abs=5e-3)
    assert hi == pytest.approx(0.999, abs=5e-3)


def test_more_evidence_narrows_the_interval():
    assert clopper_pearson(0, 500)[1] < clopper_pearson(0, 104)[1] < clopper_pearson(0, 10)[1]
    assert clopper_pearson(100, 100)[0] > clopper_pearson(16, 16)[0]


@pytest.mark.parametrize("k,n", [(-1, 10), (11, 10), (0, 0), (1, -5)])
def test_impossible_inputs_are_rejected(k, n):
    with pytest.raises(ValueError):
        clopper_pearson(k, n)


def test_the_claims_table_matches_the_evaluation(request):
    """Guards against the table drifting from the stamped results the way the prose did."""
    import json
    from pathlib import Path

    results = Path(__file__).resolve().parents[1] / "eval" / "results.json"
    if not results.exists():  # pragma: no cover
        pytest.skip("eval/results.json not present")
    rows = json.loads(results.read_text(encoding="utf-8"))["rows"]
    by_kind: dict[str, list[dict]] = {}
    for r in rows:
        by_kind.setdefault(r["kind"], []).append(r)

    claims = {label: (k, n) for label, k, n, _ in CLAIMS}
    assert claims["benign hard-blocked"] == (0, len(by_kind["benign"]))
    assert claims["designed attacks blocked"][1] == len(by_kind["malicious"])
    assert claims["incident reconstructions blocked"][1] == len(by_kind["incident"])
    for kind, label in (("redteam", "author red-team blocked"),
                        ("redteam-ind", "model-suggested red-team blocked")):  # fmt: skip
        k, n = claims[label]
        blocked = sum(1 for r in by_kind[kind] if r["outcomes"]["full"] == "Blocked")
        assert (k, n) == (blocked, len(by_kind[kind])), label
