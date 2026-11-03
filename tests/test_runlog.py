from pathlib import Path

from brain.llm import LlmOutcome
from brain.pipeline import analyze
from brain.runlog import behavior_atlas, build_record, render_dashboard
from brain.webhook import PullRequestEvent
from shared.contract import DetonateResult
from tests.test_intent import meta

FIXTURES = Path(__file__).parent / "fixtures"
R02 = DetonateResult.model_validate_json((FIXTURES / "detonate_real_r02.json").read_text())


def event(title: str = "Add dep", repo_private: bool = False) -> PullRequestEvent:
    return PullRequestEvent(
        delivery_id="d", action="opened", installation_id=1, account_login="o", owner="o",
        repo="r", number=12, head_sha="a" * 40, head_clone_url="https://github.com/o/r.git",
        is_fork=False, repo_private=repo_private, title=title,
    )  # fmt: skip


def analysis_for(result: DetonateResult):
    return analyze(result, meta(), "", lambda *a, **k: LlmOutcome("m", error="x"), job_id="j",
                   enrich=lambda r: r)  # fmt: skip


def test_record_summarizes_a_run():
    rec = build_record(event(), analysis_for(R02), "job", "2026-11-02 00:00")
    assert rec["repo"] == "o/r" and rec["pr"] == 12 and rec["verdict"] == "Blocked"
    assert "tinycolor-recon" in rec["packages_ran_scripts"]
    assert "CRED_FILE_ACCESS" in rec["rules"]


def test_private_repo_produces_no_record_for_the_public_dashboard():
    """The dashboard is public and unauthenticated: a private repo's name, PR title and the
    hosts its install contacted must never be stored at all, not merely hidden on render."""
    assert build_record(event(repo_private=True), analysis_for(R02), "job", "t") is None


def test_dashboard_escapes_untrusted_pr_title_and_rules():
    rec = {
        "ts": "t", "repo": "o/r", "pr": 1, "verdict": "Blocked", "conclusion": "failure",
        "title": "<img src=x onerror=alert(1)> [click](http://evil)", "sha": "abc1234",
        "rules": ["NET_RAW_IP"], "packages_ran_scripts": ["evil<script>"],
        "hosts": ["203.0.113.10"], "binaries": ["curl"], "cost_usd": 0.01, "detonation_s": 2.0,
    }  # fmt: skip
    page = render_dashboard([rec])
    assert "<img src=x" not in page and "<script>" not in page
    assert "&lt;img" in page and "Blocked" in page and "203.0.113.10" in page


# --- escaping, systemically ---------------------------------------------------------------
#
# The dashboard is public and unauthenticated, and `brain/runlog.py` says in its own docstring
# that the page "entity-encodes every value exactly as the PR comments do". The test above
# checks two fields. These check all of them, because the audit that produced them found one
# that was not escaped: `detonation_s` was interpolated raw. It was not exploitable - the value
# is a pydantic float, so `str()` of it cannot contain markup - but it contradicted the stated
# invariant, and the field beside it (`pr`) is escaped despite also being an int, so escaping
# everything was plainly the intent. Fixed in the same commit as these tests.
#
# Mutation results (_esc() stripped from one site at a time; "rest" = suite minus these tests):
#
# | Site stripped of _esc() | these tests | rest |
# |---|---|---|
# | title, as element text | caught | caught |
# | title, inside the HTML attribute | caught | caught |
# | repo | caught | missed |
# | verdict | caught | missed |
# | ts | caught | missed |
# | detonation_s (the gap above) | caught | missed |
# | rules list | caught | missed |
# | atlas package name | caught | caught |
# | atlas host list | caught | missed |
# | verdict tally | caught | missed |
#
# 10/10, 7 of them by these tests alone. The three the rest of the suite also catches are the
# two title sites and the atlas package - the fields the older targeted test already covered.

MARKER = "zqxmarker"
# Includes both quote styles: the title is interpolated into a single-quoted HTML attribute,
# where an unescaped `'` would break out of the attribute entirely.
WEB_PAYLOAD = (
    f"{MARKER} <img src=x onerror=alert(1)> <script>alert(1)</script> "
    f"\"' ></td></tr><tr><td>{MARKER}breakout"
)
# Sequences that must never appear raw, however the page is structured.
NEVER_RAW = ("<img", "<script", f"<td>{MARKER}breakout")


def _benign_record() -> dict:
    return {
        "ts": "2026-11-03 00:00", "repo": "o/r", "pr": 1, "verdict": "Blocked",
        "conclusion": "failure", "title": "bump a dep", "sha": "abc1234",
        "rules": ["NET_RAW_IP"], "packages_ran_scripts": ["pkg"],
        "hosts": ["203.0.113.10"], "binaries": ["curl"],
        "cost_usd": 0.01, "detonation_s": 2.0,
    }  # fmt: skip


def test_no_field_in_a_run_record_can_inject_markup_into_the_public_dashboard():
    hostile = dict(_benign_record())
    # Every field that carries sandbox- or PR-derived text. `cost_usd` is excluded because it
    # is formatted as a float (`:.4f`), so a string there raises rather than injecting.
    for key in ("ts", "repo", "pr", "verdict", "conclusion", "title", "sha", "detonation_s"):
        hostile[key] = WEB_PAYLOAD
    for key in ("rules", "packages_ran_scripts", "hosts", "binaries"):
        hostile[key] = [WEB_PAYLOAD]

    benign_page, page = render_dashboard([_benign_record()]), render_dashboard([hostile])
    assert MARKER in page, "payload never reached the page; the test proves nothing"
    for raw in NEVER_RAW:
        assert raw not in page, raw
    # Tags the payload also contains, which legitimately appear in the page: no net new ones.
    for tag in ("</td>", "</tr>", "<tr>", "</table>"):
        assert page.count(tag) == benign_page.count(tag), tag
    assert "&lt;img" in page and "&#x27;" in page  # escaped, not stripped


def test_the_title_attribute_cannot_be_broken_out_of():
    """`title` is the one value placed inside an HTML attribute rather than element text, so
    it is the only field where an unescaped quote changes the markup instead of the content."""
    page = render_dashboard([{**_benign_record(), "title": f"' onmouseover=alert(1) x='{MARKER}"}])
    # The breakout signature is a *raw* quote followed by the handler. `html.escape` leaves
    # `=` and spaces alone, so `onmouseover=alert(1)` survives as attribute text either way -
    # what makes it inert is that the quotes around it became entities.
    assert "' onmouseover=" not in page
    assert "&#x27; onmouseover=" in page and MARKER in page


def test_a_record_missing_newer_fields_still_renders():
    """Records are read back from a Modal Dict written by earlier versions of the schema. The
    dashboard is public, so one stale record must not take the whole page down."""
    page = render_dashboard([{"ts": "t", "repo": "o/r", "pr": 1, "verdict": "Clean"}])
    assert "o/r" in page and "Clean" in page


def test_atlas_aggregates_hosts_and_binaries_by_package():
    recs = [
        {"packages_ran_scripts": ["p"], "hosts": ["a.com"], "binaries": ["node"]},
        {"packages_ran_scripts": ["p"], "hosts": ["b.com"], "binaries": ["curl"]},
    ]
    atlas = behavior_atlas(recs)
    assert atlas["p"]["hosts"] == {"a.com", "b.com"}
    assert atlas["p"]["binaries"] == {"node", "curl"}


def test_empty_dashboard_renders():
    page = render_dashboard([])
    assert "no runs yet" in page and "PR Detonator" in page
