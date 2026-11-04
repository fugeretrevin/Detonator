"""Stale-check reconciliation: no check run stays in progress forever.

`detonate_job` completes its check on every path it controls, but a hard Modal timeout or a
killed container skips the exception handler and leaves the check "in progress". The webhook
records each check run it creates; the job removes the record once the check is complete; a
scheduled sweep fails closed on anything still open well past the job's timeout.

A late job can also lose a race: if the PR got a new head while the job ran, the job's check
run still belongs to its own commit (GitHub keys checks by SHA), but its comment would
overwrite the newer head's report. `head_moved` lets the job skip comment and review then.
"""

import logging
from dataclasses import asdict, dataclass
from typing import Protocol

import httpx

logger = logging.getLogger(__name__)

# detonate_job's Modal timeout is 600 s; leave room for queueing and cold starts.
STALE_AFTER_S = 900
STALE_TITLE = "Could not verify this PR"
STALE_SUMMARY = (
    "The detonation job stopped without reporting a result (killed or timed out), so this "
    "commit was never verified. Failing closed. Push a commit or re-run the check to retry."
)


@dataclass(frozen=True)
class PendingCheck:
    installation_id: int
    owner: str
    repo: str
    head_sha: str
    check_run_id: int
    started_at: float

    @property
    def key(self) -> str:
        return pending_key(self.check_run_id)

    def to_dict(self) -> dict:
        return asdict(self)


def pending_key(check_run_id: int) -> str:
    return f"check:{check_run_id}"


class ChecksApi(Protocol):
    def get_check_run(
        self, installation_id: int, owner: str, repo: str, check_run_id: int
    ) -> dict: ...

    def complete_check_run(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        check_run_id: int,
        conclusion: str,
        title: str,
        summary: str,
    ) -> None: ...


def reconcile(pending: dict[str, dict], gh: ChecksApi, now: float) -> dict[str, str]:
    """Decide each pending check. Returns {key: action}; the caller drops keys whose action
    isn't "waiting" or "retry".

    Actions: "waiting" (not stale yet), "done" (already completed by the job), "failed"
    (stale and still open: completed as failure), "gone" (repo or installation no longer
    reachable), "dropped" (unreadable record), "retry" (transient error: try next sweep).
    """
    actions: dict[str, str] = {}
    for key, raw in pending.items():
        try:
            check = PendingCheck(**raw)
        except TypeError:
            actions[key] = "dropped"
            continue
        if now - check.started_at < STALE_AFTER_S:
            actions[key] = "waiting"
            continue
        loc = (check.installation_id, check.owner, check.repo)
        try:
            run = gh.get_check_run(*loc, check.check_run_id)
            if run.get("status") == "completed":
                actions[key] = "done"
                continue
            gh.complete_check_run(*loc, check.check_run_id, "failure", STALE_TITLE, STALE_SUMMARY)
            logger.warning("stale check %s/%s %s (%s) failed closed",
                           check.owner, check.repo, check.check_run_id, check.head_sha)  # fmt: skip
            actions[key] = "failed"
        except httpx.HTTPStatusError as exc:
            # 404/403: repo deleted, app uninstalled or access revoked; nothing left to fix.
            gone = exc.response.status_code in (403, 404)
            actions[key] = "gone" if gone else "retry"
        except httpx.HTTPError:
            actions[key] = "retry"
    return actions


def head_moved(current_head_sha: str, job_head_sha: str) -> bool:
    """True if the PR's head is no longer the commit this job detonated."""
    return current_head_sha != job_head_sha
