"""Best-of-N escalation: ask the model more than once and keep the worst answer.

Temperature 0 is not determinism. On the eval, `m12-domain-exfil` came back `malicious`
(HIGH, blocks) on three trials and `suspicious` (LOW, mergeable) on two, from identical
telemetry — so a single call makes the verdict a coin flip for any case whose rules-level
signal is only LOW.

Taking the **most severe** answer across N calls is safe by construction rather than by
tuning, because `brain.verdict.combine` computes `max(rule_level, model_level, extra_level)`:
model output can only ever *raise* severity above the rules floor. Keeping the worst of N
samples can therefore never clear something a single call would have blocked, and it never
touches a rule hit. It is monotone in N.

What it costs: the same monotonicity makes a benign ⚠️ more likely. If the model says
`suspicious` about a vendor CDN one time in five, N=3 surfaces that most of the time. This
trades attack stability for benign review noise, and the exchange rate is an empirical
question — `eval/repeat.py --arms sampled` measures both directions. `MODEL_SAMPLES` is 1 by
default, so nothing changes until a measured run says it should.

A sample that errors is not a vote: errors are dropped, and only if *every* sample fails does
the outcome stay an error (which `verdict.py` then treats as model-unavailable).
"""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from brain.llm import LlmOutcome
from brain.verdict import llm_level

# 1 = today's behaviour (one call). Raise only on measured evidence; see docs/WEAKPOINTS.md W2.
MODEL_SAMPLES = 1
MAX_SAMPLES = 5


def worst(outcomes: list[LlmOutcome]) -> LlmOutcome:
    """The most severe outcome, preferring a real verdict over an error.

    Ties keep the first, so a single sample is returned unchanged. An outcome carrying no
    verdict only wins when nothing else has one."""
    usable = [o for o in outcomes if o.verdict is not None]
    if not usable:
        return outcomes[0] if outcomes else LlmOutcome("none", error="no samples")
    return max(usable, key=lambda o: llm_level(o.verdict))


def sample_analysis(
    llm,
    metadata,
    hits,
    view,
    diff,
    contract,
    guilty,
    *,
    samples: int | None = None,
    needs_more: Callable[[LlmOutcome], bool] | None = None,
) -> LlmOutcome:
    """Call the analysis once, then re-sample only if `needs_more` says the answer is borderline.

    `samples<=1` calls exactly once, so the default path is unchanged — no extra latency, no
    extra cost, no behavioural difference from calling `llm` directly.

    Why conditional. Sampling every PR three times measured at **$0.045–$0.054 per PR** against
    a pre-registered $0.04 budget, so unconditional N=3 was rejected on cost. But the flip only
    ever *matters* in the ⚠️ band: a Blocked verdict cannot be undone by a worse sample
    (`combine` takes a max), and ⚠️ was about 4 of 142 cases in the eval. Re-sampling only
    there buys the same stability for roughly a tenth of a cent per PR on average.

    `needs_more` receives the first outcome and returns True to draw the rest. The caller owns
    that decision because only it knows the rules floor; `pipeline.analyze` passes a predicate
    that fires when the combined verdict would be "Needs review"."""
    from brain.pinpoint import for_prompt

    n = MODEL_SAMPLES if samples is None else samples
    n = max(1, min(n, MAX_SAMPLES))

    def once() -> LlmOutcome:
        return llm(metadata, hits, view, diff, contract.for_prompt(),
                   guilty=for_prompt(guilty) or None)  # fmt: skip

    first = once()
    if n == 1 or (needs_more is not None and not needs_more(first)):
        return first
    # Independent samples, so the remaining N-1 cost one call's latency between them.
    with ThreadPoolExecutor(max_workers=n - 1) as pool:
        rest = [f.result() for f in [pool.submit(once) for _ in range(n - 1)]]
    return worst([first, *rest])
