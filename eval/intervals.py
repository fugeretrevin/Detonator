"""Exact (Clopper-Pearson) binomial confidence intervals for the headline proportions.

Small denominators invite overconfidence. "16 of 16 attacks blocked" and "0 blocked of 104
benign" are both real results, but neither supports a population claim, and the honest way to
say so is to print the interval next to the point estimate.

Exact rather than normal-approximation, because the normal approximation is invalid at exactly
the proportions here (0/104 and 16/16, where it gives a zero-width interval). Clopper-Pearson
inverts the binomial test:

    for 0 successes in n:   upper = 1 - (alpha/2) ** (1/n),  lower = 0
    for n successes in n:   lower = (alpha/2) ** (1/n),      upper = 1
    otherwise:              bisect the exact binomial tail

Implemented with `math.comb`, so no SciPy dependency and the arithmetic is exact rather than
approximated.

**What an interval here does and does not mean.** It quantifies sampling error *if* the cases
were drawn independently from the population being described. They were not: the benign set is
hand-picked popular packages, the attacks are author-written, and repeated trials of the same
case are not independent. So these are a floor on uncertainty, not a generalisation guarantee -
a point the intervals make harder to forget, which is why they are here.

Run: `python -m eval.intervals`
"""

import math

ALPHA = 0.05  # two-sided 95%


def _binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p), summed exactly."""
    return sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k + 1))


def _solve(f, goal: float, increasing: bool) -> float:
    """Bisect f(p) = goal on [0, 1].

    The two tails move in opposite directions in p, and treating them alike silently inverts
    one of them: the first version of this file reported a lower bound ABOVE the upper bound
    for 1/421, and 0.0% lower bounds for 9/10 and 19/20. Hence the explicit flag.
    """
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2
        below = f(mid) < goal
        if below == increasing:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def clopper_pearson(k: int, n: int, alpha: float = ALPHA) -> tuple[float, float]:
    """Exact two-sided interval for k successes in n trials."""
    if not 0 <= k <= n or n <= 0:
        raise ValueError(f"k={k} n={n}")
    half = alpha / 2
    if k == 0:
        return 0.0, 1.0 - half ** (1 / n)
    if k == n:
        return half ** (1 / n), 1.0
    # Lower: p where P(X >= k) = half. P(X >= k) increases with p.
    lower = _solve(lambda p: 1 - _binom_cdf(k - 1, n, p), half, increasing=True)
    # Upper: p where P(X <= k) = half. P(X <= k) decreases with p.
    upper = _solve(lambda p: _binom_cdf(k, n, p), half, increasing=False)
    return lower, upper


CLAIMS: tuple[tuple[str, int, int, str], ...] = (
    ("benign hard-blocked", 0, 104, "0 of 104 popular packages blocked, every arm"),
    ("benign hard-blocked (verified only)", 0, 98, "excluding the 6 we could not verify"),
    ("designed attacks blocked", 16, 16, "full pipeline"),
    ("incident reconstructions blocked", 2, 2, "ua-parser-js, Shai-Hulud"),
    ("author red-team blocked", 9, 10, "rt08 is an open miss"),
    ("model-suggested red-team blocked", 10, 10, "not a blind external set"),
    ("red-team blocked, both sets", 19, 20, "worst repeated trial: 18/20"),
    ("sweep blocks", 1, 421, "unlabelled packages: an alert rate, not accuracy"),
)


def main() -> None:
    print("Exact (Clopper-Pearson) two-sided 95% intervals\n")
    print(f"{'claim':38s} {'point':>8s}   {'95% interval':>18s}   note")
    print("-" * 104)
    for label, k, n, note in CLAIMS:
        lo, hi = clopper_pearson(k, n)
        print(f"{label:38s} {k:4d}/{n:<4d} {100 * lo:7.1f}% - {100 * hi:6.1f}%   {note}")
    print(
        "\nThese bound sampling error only, and assume independent draws from the population "
        "described.\nThese cohorts are hand-selected, so treat each interval as a floor on "
        "uncertainty rather than\na generalisation guarantee. See this module's docstring."
    )


if __name__ == "__main__":
    main()
