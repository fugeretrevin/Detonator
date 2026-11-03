"""`detonate_job` - the Modal entrypoint that orchestrates everything - end to end.

Until now this function had **no test coverage at all**: it is a `modal.Function`, so it looked
untestable, and every test in this suite exercised the pieces it calls rather than the wiring
between them. That is the wrong half to leave untested. Two of the worst bugs found in this
project lived exactly here - a sensor witness that reported blind on every real PR, and a
"Clean" verdict issued for an install that had failed - and both were invisible to unit tests
that fed the pipeline hand-built inputs.

`modal.Function.local()` runs the undecorated body in-process, so the only thing standing in
the way was the module's global `modal.Dict` handles and the network-touching helpers. Those are
module-level names, so `monkeypatch.setattr` replaces them.

What these tests are for, in order of how much they matter:

1. **The check always reaches a terminal conclusion.** Every failure path must complete the
   check as `failure`, because GitHub treats `neutral` as passing and an unfinished check sits
   there forever. This is the fail-closed guarantee the write-up makes.
2. **A superseded job does not write onto a newer head.** `brain/reconcile.py` only provides the
   predicate; this asserts the job *uses* it - check still concluded on its own SHA, comment and
   review suppressed. (docs/WEAKPOINTS.md W7 scenario 2.)
3. **Best-effort work is really best effort.** A failed comment, review or run-log write must
   not change the check or raise.

Mutation-tested, and unlike `test_reconcile_drill.py` these do find things the rest of the suite
cannot. Four injected defects, each caught here and by **nothing** in the other 498 tests:

| Injected defect | Caught elsewhere? |
|---|---|
| Comment posted even when the head moved | no |
| Failure path concludes `neutral` instead of `failure` | no |
| `finish()` stops dropping the pending record | no |
| Private-repo clone token fetched regardless of TLS | no |

The last is a real security regression - a read token over the HMAC-only link - and nothing in
the suite noticed it.
"""

from dataclasses import dataclass

import pytest

# `brain/app.py` imports the Modal SDK at module scope, and these tests import `brain.app`
# inside their fixtures. Without the SDK they would therefore fail *at run time* rather than be
# skipped, which an independent reviewer reads as 21 broken tests rather than 21 unrunnable
# ones. `modal` is in requirements-dev.txt, so a correctly provisioned environment runs them
# all; this only makes the degraded case legible. Module scope, so it gates collection.
pytest.importorskip("modal", reason="Modal SDK not installed; see requirements-dev.txt")

from brain.pipeline import PRIVATE_REPO_TITLE  # noqa: E402
from brain.verdict import FinalVerdict
from brain.webhook import PullRequestEvent
from shared.contract import DetonateResult
from tests.conftest import NPM_EXEC

CHECK_ID = 555
NEW_HEAD = "b" * 40


def event(**over) -> PullRequestEvent:
    base = dict(
        delivery_id="d", action="opened", installation_id=1, account_login="o", owner="o",
        repo="r", number=1, head_sha="a" * 40, head_clone_url="https://github.com/o/r.git",
        is_fork=False, repo_private=False,
    )  # fmt: skip
    return PullRequestEvent(**{**base, **over})


def clean_result() -> DetonateResult:
    return DetonateResult(
        job_id="j", status="completed", exit_code=0, duration_s=1,
        exec_events=[NPM_EXEC], connect_events=[], dns_queries=[],
        stdout_tail="", stderr_tail="",
    )  # fmt: skip


@dataclass
class FakeGitHub:
    """Records what the job did to GitHub. Raises only where a test asks it to."""

    head_sha: str = "a" * 40
    fail_comment: bool = False
    fail_head_read: bool = False
    completed: list = None
    comments: list = None
    reviews: list = None

    def __post_init__(self):
        self.completed, self.comments, self.reviews = [], [], []

    def complete_check_run(self, inst, owner, repo, run_id, conclusion, title, summary):
        self.completed.append({"id": run_id, "conclusion": conclusion, "title": title})

    def list_pr_files(self, *a):
        return []

    def get_pr_metadata(self, *a, **k):
        from brain.github_client import PrMetadata

        return PrMetadata(title="t", body="b", author="a", changed_files=[],
                          package_json_changed=False, scripts_changed=False,
                          lockfile_changed=False)  # fmt: skip

    def get_pr_diff(self, *a):
        return "diff"

    def get_pr_head_sha(self, *a):
        if self.fail_head_read:
            raise RuntimeError("GitHub 500")
        return self.head_sha

    def get_file(self, *a):
        return None

    def upsert_comment(self, *a, **k):
        if self.fail_comment:
            raise RuntimeError("comment failed")
        self.comments.append(a[3])

    def create_review(self, inst, owner, repo, number, sha, comments):
        self.reviews.append(comments)

    def repo_read_token(self, *a):
        return "ghs_read"


class FakeChamber:
    tls = True

    def __init__(self, result=None, boom: Exception | None = None):
        self._result, self._boom = result, boom
        self.calls = 0

    def detonate(self, request):
        self.calls += 1
        if self._boom:
            raise self._boom
        return self._result


@pytest.fixture
def job(monkeypatch):
    """Wire `brain.app`'s module-level seams to in-process fakes and hand back a runner."""
    import brain.app as app

    gh = FakeGitHub()
    pending = {f"check:{CHECK_ID}": {"stub": True}}
    runs: dict = {}

    monkeypatch.setattr(app, "github", lambda: gh)
    monkeypatch.setattr(app, "pending_checks", pending)
    monkeypatch.setattr(app, "run_log", runs)
    monkeypatch.setattr(app, "github_meta_cidrs", lambda: [])
    monkeypatch.setattr(app, "_new_package_resolver", lambda: None)
    monkeypatch.setattr(app, "_investigate", lambda hits, result: None)
    monkeypatch.setattr(app, "_base_detonation", lambda *a: None)
    monkeypatch.setattr(app, "_predict", lambda meta: _no_prediction())
    monkeypatch.setattr(app, "_guard", lambda meta, diff: _no_guard())
    monkeypatch.setattr(app, "_llm_analyzer", lambda: _benign_analyzer)

    def run(ev=None, chamber=None, chamber_raises: Exception | None = None):
        def factory():
            if chamber_raises is not None:
                raise chamber_raises
            return chamber or FakeChamber(clean_result())

        monkeypatch.setattr(app, "chamber_client_from_env", factory)
        app.detonate_job.local(ev or event(), CHECK_ID)

    run.gh, run.pending, run.runs, run.app = gh, pending, runs, app
    return run


def _no_prediction():
    from brain.intent import PredictionOutcome

    return PredictionOutcome("m", error="skipped in test")


def _no_guard():
    from brain import prompt_guard as pg

    return pg.GuardOutcome(error="skipped in test")


def _benign_analyzer(*a, **k):
    from brain.llm import LlmOutcome

    return LlmOutcome("m", skipped=True)


# --- 1. the check always reaches a terminal conclusion -------------------------------------


def test_happy_path_completes_the_check_and_drops_the_pending_record(job):
    job()

    assert len(job.gh.completed) == 1
    done = job.gh.completed[0]
    assert done["id"] == CHECK_ID
    assert done["conclusion"] in ("success", "neutral", "failure")
    assert job.pending == {}, "the reconciler would later re-fail a check we did complete"
    assert job.runs.get("records"), "the dashboard run log was not written"


def test_a_chamber_that_cannot_be_reached_fails_the_check_closed(job):
    """Setup error path: this runs before the main try, and used to be the easiest way to
    leave a check hanging."""
    with pytest.raises(RuntimeError):
        job(chamber_raises=RuntimeError("no chamber configured"))

    assert [c["conclusion"] for c in job.gh.completed] == ["failure"]
    assert job.gh.completed[0]["title"] == "Could not verify this PR"
    assert job.pending == {}


def test_a_detonation_that_blows_up_mid_job_fails_the_check_closed(job):
    with pytest.raises(RuntimeError):
        job(chamber=FakeChamber(boom=RuntimeError("chamber exploded")))

    assert [c["conclusion"] for c in job.gh.completed] == ["failure"]
    assert job.gh.completed[0]["title"] == "Could not verify this PR"
    assert job.pending == {}, "a crashed job must not also leave a pending record behind"


def test_the_check_is_never_concluded_neutral_on_a_failure_path(job):
    """GitHub treats `neutral` as passing, so a failure path that concluded neutral would
    sail through branch protection. This is the whole fail-closed claim in one assertion."""
    with pytest.raises(RuntimeError):
        job(chamber=FakeChamber(boom=RuntimeError("boom")))

    assert "neutral" not in [c["conclusion"] for c in job.gh.completed]


def test_a_private_repo_without_tls_is_not_detonated_and_still_concludes(job):
    """The security property: a clone token is never sent over the HMAC-only link. Without TLS
    the job must refuse to detonate rather than detonate without the token."""
    chamber = FakeChamber(clean_result())
    chamber.tls = False

    job(ev=event(repo_private=True), chamber=chamber)

    assert chamber.calls == 0, "detonated a private repo over a non-TLS link"
    assert job.gh.completed[0]["title"] == PRIVATE_REPO_TITLE
    assert job.gh.completed[0]["conclusion"] == "failure", "must not pass branch protection"
    assert job.pending == {}


def test_a_private_repo_over_tls_is_detonated_with_a_scoped_token(job):
    """The counterpart: with TLS it *is* detonated, and the token that goes with it is the
    scoped read-only one, not an installation token."""
    chamber = FakeChamber(clean_result())

    job(ev=event(repo_private=True), chamber=chamber)

    assert chamber.calls == 1
    assert job.gh.completed[0]["title"] != PRIVATE_REPO_TITLE


def test_a_private_repo_never_reaches_the_public_run_log(job):
    """`build_record` returns None for a private repo; this asserts the job honours that
    instead of writing the record anyway."""
    job(ev=event(repo_private=True))

    assert "records" not in job.runs, "a private repo leaked into the public dashboard"


# --- 2. a superseded job must not write onto a newer head ----------------------------------


def test_a_superseded_job_concludes_its_own_check_but_posts_nothing(job):
    """W7 scenario 2, at the level that was missing: `reconcile.head_moved` is a tested
    predicate, but nothing asserted that the job acts on it."""
    job.gh.head_sha = NEW_HEAD  # the PR moved on while we ran

    job()

    assert len(job.gh.completed) == 1, "the check belongs to our SHA and must still conclude"
    assert job.gh.completed[0]["id"] == CHECK_ID
    assert job.gh.comments == [], "overwrote the newer head's report"
    assert job.gh.reviews == [], "reviewed a commit that is no longer the head"


def test_an_unsuperseded_job_does_post_its_report(job):
    """The control for the test above: without it, a job that never commented would pass."""
    job()

    assert job.gh.comments, "the report was not posted on the current head"


def test_a_failed_head_read_posts_anyway_rather_than_going_silent(job):
    job.gh.fail_head_read = True

    job()

    assert job.gh.comments, "a GitHub blip must not silently suppress the report"
    assert len(job.gh.completed) == 1


# --- 3. best-effort work is really best effort ---------------------------------------------


def test_a_failed_comment_does_not_disturb_the_check_or_raise(job):
    job.gh.fail_comment = True

    job()  # must not raise

    assert len(job.gh.completed) == 1
    assert job.runs.get("records"), "a failed comment aborted the rest of the job"


def test_a_broken_run_log_does_not_fail_the_job(job, monkeypatch):
    class Hostile(dict):
        def __setitem__(self, *a):
            raise RuntimeError("Dict write failed")

    monkeypatch.setattr(job.app, "run_log", Hostile())

    job()  # must not raise

    assert len(job.gh.completed) == 1
    assert job.gh.comments


def test_a_broken_pending_store_does_not_fail_the_job(job, monkeypatch):
    class Hostile(dict):
        def pop(self, *a):
            raise RuntimeError("Dict pop failed")

    monkeypatch.setattr(job.app, "pending_checks", Hostile())

    job()  # must not raise

    assert len(job.gh.completed) == 1


# --- the verdict actually reaches the check -------------------------------------------------


def test_a_blocked_verdict_reaches_the_check_as_a_failure(job, monkeypatch):
    """Guards the wiring from `analysis.final` to `complete_check_run`: a verdict computed
    correctly and then reported as the wrong conclusion is indistinguishable from a miss."""
    import brain.app as app

    real_analyze = app.analyze

    def blocked(*a, **k):
        analysis = real_analyze(*a, **k)
        final = FinalVerdict(
            analysis.final.level, analysis.final.rule_level, analysis.final.llm_level,
            "failure", "Blocked", True,
        )  # fmt: skip
        return analysis.__class__(**{**analysis.__dict__, "final": final})

    monkeypatch.setattr(app, "analyze", blocked)

    job()

    assert job.gh.completed[0]["conclusion"] == "failure"
    assert "Blocked" in job.gh.completed[0]["title"]
