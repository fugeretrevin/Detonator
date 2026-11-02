import httpx

from brain.reconcile import (
    STALE_AFTER_S,
    STALE_TITLE,
    PendingCheck,
    head_moved,
    pending_key,
    reconcile,
)

NOW = 1_800_000_000.0


def pending(check_run_id: int, age_s: float) -> PendingCheck:
    return PendingCheck(7, "acme", "web", "a" * 40, check_run_id, started_at=NOW - age_s)


class FakeChecks:
    def __init__(self, statuses: dict[int, str | Exception]):
        self.statuses = statuses
        self.completed: list[tuple] = []

    def get_check_run(self, installation_id, owner, repo, check_run_id):
        status = self.statuses[check_run_id]
        if isinstance(status, Exception):
            raise status
        return {"id": check_run_id, "status": status}

    def complete_check_run(self, installation_id, owner, repo, check_run_id, conclusion, title,
                           summary):  # fmt: skip
        self.completed.append((check_run_id, conclusion, title))


def http_error(code: int) -> httpx.HTTPStatusError:
    req = httpx.Request("GET", "https://api.github.test/x")
    return httpx.HTTPStatusError("err", request=req, response=httpx.Response(code, request=req))


def run(checks: list[PendingCheck], gh: FakeChecks) -> dict[str, str]:
    return reconcile({c.key: c.to_dict() for c in checks}, gh, NOW)


def test_stale_open_check_fails_closed():
    gh = FakeChecks({1: "in_progress"})
    assert run([pending(1, STALE_AFTER_S + 1)], gh) == {pending_key(1): "failed"}
    assert gh.completed == [(1, "failure", STALE_TITLE)]  # never neutral: that passes protection


def test_queued_counts_as_open():
    gh = FakeChecks({1: "queued"})
    assert run([pending(1, STALE_AFTER_S + 1)], gh) == {pending_key(1): "failed"}


def test_young_check_is_left_alone_without_calling_github():
    gh = FakeChecks({})  # any lookup would KeyError
    assert run([pending(1, STALE_AFTER_S - 1)], gh) == {pending_key(1): "waiting"}
    assert gh.completed == []


def test_check_the_job_completed_is_just_dropped():
    gh = FakeChecks({1: "completed"})
    assert run([pending(1, STALE_AFTER_S * 3)], gh) == {pending_key(1): "done"}
    assert gh.completed == []  # never overwrite a real verdict


def test_unreachable_repo_is_dropped_but_transient_errors_retry():
    gh = FakeChecks({1: http_error(404), 2: http_error(403), 3: http_error(502),
                     4: httpx.ConnectError("down")})  # fmt: skip
    old = STALE_AFTER_S + 1
    assert run([pending(i, old) for i in (1, 2, 3, 4)], gh) == {
        pending_key(1): "gone",
        pending_key(2): "gone",
        pending_key(3): "retry",
        pending_key(4): "retry",
    }


def test_unreadable_record_is_dropped():
    assert reconcile({"check:9": {"bogus": 1}}, FakeChecks({}), NOW) == {"check:9": "dropped"}


def test_one_failure_does_not_stop_the_sweep():
    gh = FakeChecks({1: httpx.ConnectError("down"), 2: "in_progress"})
    old = STALE_AFTER_S + 1
    actions = run([pending(1, old), pending(2, old)], gh)
    assert actions[pending_key(2)] == "failed"


def test_record_round_trips():
    check = pending(5, 10)
    assert PendingCheck(**check.to_dict()) == check
    assert check.key == "check:5"


def test_head_moved():
    assert head_moved("b" * 40, "a" * 40)
    assert not head_moved("a" * 40, "a" * 40)
