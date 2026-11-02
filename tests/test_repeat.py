from itertools import cycle
from types import SimpleNamespace

from brain.evidence import Grounding, Rejected
from eval.repeat import case_stats, run_trials, summarize


class FakeCase:
    def __init__(self, id, kind):
        self.id, self.kind = id, kind

    def metadata(self):
        return {"title": self.id}

    def diff(self):
        return ""


def scripted(*titles, error=None):
    """An analyze() stand-in that returns the given verdict titles in turn."""
    it = cycle(titles)

    def analyze(result, meta, diff, llm, **kwargs):
        g = Grounding(rejected=[Rejected("exec", "x")])
        return SimpleNamespace(final=SimpleNamespace(title=next(it)),
                               llm=SimpleNamespace(error=error), grounding=g)  # fmt: skip

    return analyze


def trials(case, titles, n=3, arms=("full",), error=None):
    predicted = []
    row = run_trials(case, None, n, arms, scripted(*titles, error=error), llm=None,
                     predict_fn=lambda m: predicted.append(m), guard=None, common={})  # fmt: skip
    return row, predicted


def test_runs_every_trial_and_predicts_once_per_trial():
    row, predicted = trials(FakeCase("m01", "malicious"), ["Blocked"], n=4)
    assert row["outcomes"]["full"] == ["Blocked"] * 4 and len(predicted) == 4
    assert len(row["grounding"]) == 4


def test_analysis_arm_alone_never_predicts():
    _, predicted = trials(FakeCase("m01", "malicious"), ["Blocked"], arms=("analysis",))
    assert predicted == []


def test_attack_that_slips_once_is_an_unsafe_pass():
    row, _ = trials(FakeCase("rt09", "redteam"), ["Blocked", "Needs review", "Blocked"])
    s = case_stats(row, "full")
    assert s["flipped"] and s["unsafe_trials"] == 1 and s["most_lenient"] == "Needs review"


def test_benign_blocked_once_counts_as_a_benign_block():
    row, _ = trials(FakeCase("cypress", "benign"), ["Clean", "Blocked", "Clean"])
    s = case_stats(row, "full")
    assert s["benign_block_trials"] == 1 and s["unsafe_trials"] == 0


def test_summary_reports_worst_cases_and_only_lists_unstable_rows():
    rows = [
        trials(FakeCase("m01", "malicious"), ["Blocked"])[0],
        trials(FakeCase("rt09", "redteam"), ["Blocked", "Clean"])[0],
        trials(FakeCase("lodash", "benign"), ["Clean"])[0],
    ]
    md = "\n".join(summarize(rows, "full", 3))
    assert "1/3 cases gave more than one outcome (rt09)" in md
    assert "1/2 attacks were mergeable" in md and "0/1 benign" in md
    assert "| rt09 |" in md and "| m01 |" not in md and "| lodash |" not in md
    assert "0/9 claims supported" in md  # 3 cases x 3 trials, one rejected claim each


def test_model_errors_are_counted():
    row, _ = trials(FakeCase("m01", "malicious"), ["Needs review"], error="HTTP 503")
    assert row["llm_errors"] == 3
    assert "Model errors across all trials: 3" in "\n".join(summarize([row], "full", 3))
