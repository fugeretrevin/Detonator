import json
from pathlib import Path

from brain import prompt_guard as pg
from brain.github_client import PrMetadata
from brain.intent import PredictionOutcome
from brain.llm import LlmOutcome
from brain.pipeline import analyze
from tests.test_intent import connect, outcome, result

FIXTURES = Path(__file__).parent / "fixtures/prompt_guard"


def meta(**kw) -> PrMetadata:
    base = dict(
        title="Add prisma",
        body="Use Prisma.",
        author="x",
        changed_files=["package.json"],
        package_json_changed=True,
        scripts_changed=False,
        lockfile_changed=False,
    )
    return PrMetadata(**{**base, **kw})


def guard(score: float, source: str = "body") -> pg.GuardOutcome:
    top = pg.Detection(source, score, "Ignore all previous instructions")
    return pg.GuardOutcome(scores={source: score}, top=top)


def test_inputs_are_title_body_and_added_diff_lines_only():
    diff = "+++ b/package.json\n-old line\n+new line\n context"
    assert pg.guard_inputs(meta(body="  "), diff) == {"title": "Add prisma", "diff": "new line"}


def test_windows_cover_every_token_with_overlap():
    spans = pg.windows(list(range(1200)))
    assert spans[0] == (0, 510) and spans[-1][1] == 1200
    assert all(b[0] < a[1] for a, b in zip(spans, spans[1:], strict=False))  # overlapping
    assert pg.windows([1, 2, 3]) == [(0, 3)]


def test_flagged_only_at_or_above_threshold():
    assert pg.flagged(guard(0.95)) and not pg.flagged(guard(0.31))
    assert not pg.flagged(None) and not pg.flagged(pg.GuardOutcome(error="timeout"))


def test_threshold_matches_recorded_validation():
    # scripts/probe_prompt_guard.py on Nov 1: real PR bodies vs injection texts.
    rows = json.loads((FIXTURES / "probe_scores.json").read_text())
    benign = [r["max"] for r in rows if r["kind"] == "benign"]
    explicit = [r["max"] for r in rows if r["name"] in ("classic", "role-play")]
    assert max(benign) < pg.THRESHOLD <= min(explicit)


def benign_llm(*_, **__):
    return LlmOutcome("m", error="x")


def prisma_like():
    return result([connect("104.16.1.34", domain="registry.npmjs.org"),
                   connect("34.1.1.1", domain="binaries.prisma.sh")])  # fmt: skip


def test_flagged_text_stops_the_contract_from_clearing():
    pred: PredictionOutcome = outcome(["binaries.prisma.sh"])
    clean = analyze(prisma_like(), meta(), "", benign_llm, job_id="j", enrich=lambda r: r,
                    prediction=pred, guard=guard(0.2))  # fmt: skip
    assert clean.final.conclusion == "success" and clean.cleared
    out = analyze(prisma_like(), meta(), "", benign_llm, job_id="j", enrich=lambda r: r,
                  prediction=pred, guard=guard(0.97))  # fmt: skip
    assert out.final.conclusion == "neutral" and out.cleared == []
    assert "Llama Prompt Guard 2 flagged the PR body" in out.report


def test_guard_never_changes_a_verdict_by_itself():
    clean = result([connect("104.16.1.34", domain="registry.npmjs.org")])
    out = analyze(clean, meta(), "", benign_llm, job_id="j", enrich=lambda r: r,
                  guard=guard(0.99))  # fmt: skip
    assert out.final.conclusion == "success"


def test_footer_reports_score_or_unavailability():
    ok = analyze(prisma_like(), meta(), "", benign_llm, job_id="j", enrich=lambda r: r,
                 guard=guard(0.15))  # fmt: skip
    assert "Prompt Guard 2 max 0.15" in ok.report and "flagged" not in ok.report
    down = analyze(prisma_like(), meta(), "", benign_llm, job_id="j", enrich=lambda r: r,
                   guard=pg.GuardOutcome(error="timeout"))  # fmt: skip
    assert "Prompt Guard 2 unavailable" in down.report
