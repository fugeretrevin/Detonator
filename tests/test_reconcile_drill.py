"""W7 fault-injection drill: the reconciler invariant, asserted end to end.

`tests/test_reconcile.py` fakes the `ChecksApi` *protocol* and `tests/test_github_client.py`
asserts the wire format, each in isolation. This composes them - real `GitHubClient`, real
`reconcile`, over HTTP, against a fake that *keeps check-run state* the way GitHub does (keyed
by id, permanently owning the `head_sha` it was created against) - and states the property the
write-up actually claims:

    no check run stays `in_progress`, and no stale success survives on any SHA.

Scenario 1 kills the job (the handler never runs, so the check is never completed) and lets the
reconciler sweep. Scenario 2 pushes a second commit while a job is in flight and asserts the
late job lands its conclusion on *its own* commit without touching the newer head's check.

**What this is not.** It was mutation-tested against four injected defects - concluding
`neutral` instead of `failure`, a wrong check-runs URL, dropping the already-completed guard,
and a PATCH that omits `status: completed` - and caught all four, but so did the existing suite
every time. It therefore adds **integration confidence and a single readable statement of the
invariant, not new defect detection**. Treat it as documentation with teeth.

Two things it cannot cover, both of which keep W7's real acceptance open (see
docs/WEAKPOINTS.md): that a hard Modal kill genuinely skips the exception handler (a property
of Modal, so `started_at` is backdated rather than waiting out the 900 s window), and that
`detonate_job` completes its check *before* consulting `head_moved` - scenario 2 hand-rolls
that order instead of calling the Modal function, which has no test coverage at all.
"""

import json

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from brain.github_client import GitHubClient
from brain.reconcile import STALE_AFTER_S, STALE_TITLE, PendingCheck, head_moved, reconcile

INSTALL, OWNER, REPO = 7, "octo", "scratch"
SHA_OLD = "a" * 40
SHA_NEW = "b" * 40


@pytest.fixture(scope="module")
def pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


class FakeChecks:
    """Minimal but stateful: POST creates an in_progress run, PATCH completes it, GET reads it.

    Mirrors the semantics the reconciler depends on - a check run is keyed by id and belongs
    permanently to the `head_sha` it was created against, so completing one can never move
    another commit's check.
    """

    def __init__(self) -> None:
        self.runs: dict[int, dict] = {}
        self._next = 1000
        self.requests: list[tuple[str, str]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path.endswith("/access_tokens"):
            return httpx.Response(
                201, json={"token": "ghs_x", "expires_at": "2999-01-01T00:00:00Z"}
            )
        assert request.headers["Authorization"] == "token ghs_x", "installation token not sent"
        self.requests.append((method, path))
        body = json.loads(request.content) if request.content else {}

        if method == "POST" and path == f"/repos/{OWNER}/{REPO}/check-runs":
            self._next += 1
            self.runs[self._next] = {
                "id": self._next,
                "head_sha": body["head_sha"],
                "status": body.get("status", "queued"),
                "conclusion": None,
                "output": body.get("output", {}),
            }
            return httpx.Response(201, json=self.runs[self._next])

        prefix = f"/repos/{OWNER}/{REPO}/check-runs/"
        if path.startswith(prefix):
            run_id = int(path[len(prefix) :])
            if run_id not in self.runs:
                return httpx.Response(404, json={"message": "Not Found"})
            if method == "GET":
                return httpx.Response(200, json=self.runs[run_id])
            if method == "PATCH":
                self.runs[run_id].update(
                    {k: v for k, v in body.items() if k in ("status", "conclusion", "output")}
                )
                return httpx.Response(200, json=self.runs[run_id])
        return httpx.Response(405, json={"message": f"unrouted {method} {path}"})

    def client(self, pem: str) -> GitHubClient:
        http = httpx.Client(
            base_url="https://api.github.test", transport=httpx.MockTransport(self.handler)
        )
        return GitHubClient("4242", pem, http=http)

    # --- what a reviewer would actually look at ---

    def open_runs(self) -> list[dict]:
        return [r for r in self.runs.values() if r["status"] != "completed"]

    def passing_runs(self) -> list[dict]:
        return [r for r in self.runs.values() if r["conclusion"] in ("success", "neutral", None)]


def test_a_killed_job_leaves_no_check_in_progress(pem):
    """Scenario 1. The webhook creates the check and records it; the job is killed, so nothing
    completes it; the reconciler must move it to a terminal *failing* conclusion."""
    gh_api = FakeChecks()
    gh = gh_api.client(pem)

    check_run_id = gh.create_check_run(INSTALL, OWNER, REPO, SHA_OLD, details_url="https://x/1")
    pending = PendingCheck(INSTALL, OWNER, REPO, SHA_OLD, check_run_id, started_at=1_000.0)
    store = {pending.key: pending.to_dict()}

    # --- the job is killed here: no finish(), so the record is never dropped ---
    assert gh_api.runs[check_run_id]["status"] == "in_progress"

    # A sweep before the window closes must not touch it (a slow job is not a dead one).
    assert reconcile(store, gh, now=1_000.0 + STALE_AFTER_S - 1) == {pending.key: "waiting"}
    assert gh_api.runs[check_run_id]["status"] == "in_progress"

    actions = reconcile(store, gh, now=1_000.0 + STALE_AFTER_S + 1)

    assert actions == {pending.key: "failed"}
    run = gh_api.runs[check_run_id]
    assert run["status"] == "completed"
    assert run["conclusion"] == "failure", "neutral or success would pass branch protection"
    assert run["output"]["title"] == STALE_TITLE
    assert run["head_sha"] == SHA_OLD, "reconciled the wrong commit"
    assert gh_api.open_runs() == []
    assert gh_api.passing_runs() == [], "a stale check must not be left passing"


def test_the_reconciler_is_idempotent_and_drops_a_check_the_job_finished(pem):
    """A second sweep must not re-PATCH a completed run, and a job that finished normally
    between sweeps is just forgotten."""
    gh_api = FakeChecks()
    gh = gh_api.client(pem)
    check_run_id = gh.create_check_run(INSTALL, OWNER, REPO, SHA_OLD)
    pending = PendingCheck(INSTALL, OWNER, REPO, SHA_OLD, check_run_id, started_at=1_000.0)
    late = 1_000.0 + STALE_AFTER_S + 1

    gh.complete_check_run(INSTALL, OWNER, REPO, check_run_id, "success", "Clean", "all good")
    patches = sum(1 for m, _ in gh_api.requests if m == "PATCH")

    assert reconcile({pending.key: pending.to_dict()}, gh, now=late) == {pending.key: "done"}
    assert sum(1 for m, _ in gh_api.requests if m == "PATCH") == patches, "re-PATCHed a done run"
    assert gh_api.runs[check_run_id]["conclusion"] == "success"


def test_a_late_job_concludes_its_own_commit_and_not_the_new_head(pem):
    """Scenario 2. A second commit arrives while the first job runs. Each commit has its own
    check run, so the late job's conclusion must land on SHA_OLD and leave SHA_NEW's check
    alone - and crucially must not leave the *new* head showing a passing check it never
    earned."""
    gh_api = FakeChecks()
    gh = gh_api.client(pem)

    old_check = gh.create_check_run(INSTALL, OWNER, REPO, SHA_OLD)
    new_check = gh.create_check_run(INSTALL, OWNER, REPO, SHA_NEW)  # the push, mid-flight

    # The late job finishes. app.py completes its check before consulting head_moved, so the
    # conclusion is written either way; only the comment and review are skipped.
    gh.complete_check_run(INSTALL, OWNER, REPO, old_check, "failure", "Blocked", "exfil")
    assert head_moved(SHA_NEW, SHA_OLD) is True, "job must know it was superseded"

    assert gh_api.runs[old_check]["conclusion"] == "failure"
    assert gh_api.runs[old_check]["head_sha"] == SHA_OLD
    assert gh_api.runs[new_check]["conclusion"] is None, "late job wrote onto the new head"
    assert gh_api.runs[new_check]["status"] == "in_progress"

    # The new head's own check is still open, so it is the reconciler's problem now. Fail closed.
    new_pending = PendingCheck(INSTALL, OWNER, REPO, SHA_NEW, new_check, started_at=2_000.0)
    reconcile({new_pending.key: new_pending.to_dict()}, gh, now=2_000.0 + STALE_AFTER_S + 1)

    assert gh_api.open_runs() == []
    assert gh_api.passing_runs() == [], "no SHA may be left passing"
    assert {r["head_sha"] for r in gh_api.runs.values()} == {SHA_OLD, SHA_NEW}


def test_a_deleted_repo_is_abandoned_not_retried_forever(pem):
    """The 404 path over real HTTP: `_request` raises HTTPStatusError, and the sweep must
    classify it as gone rather than retrying a check that can never be completed."""
    gh_api = FakeChecks()
    gh = gh_api.client(pem)
    missing = PendingCheck(INSTALL, OWNER, REPO, SHA_OLD, 424_242, started_at=1_000.0)

    actions = reconcile({missing.key: missing.to_dict()}, gh, now=1_000.0 + STALE_AFTER_S + 1)

    assert actions == {missing.key: "gone"}
