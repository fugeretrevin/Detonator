"""`brain.app._handle` - the webhook entry point, driven with genuinely signed bodies.

`tests/test_webhook.py` covers `handle_webhook`, the pure decision. This covers what `app.py`
does *with* that decision, which is where the ordering guarantee lives:

    the pending record must be written **before** the job is spawned.

If a spawned job dies immediately - a Modal cold-start failure, an OOM kill - the only thing
that will ever close its check is the reconciler, and the reconciler only knows about checks
that made it into `pending_checks`. Record after spawn and that check can hang forever, which is
precisely the failure W7 exists to prevent. Nothing asserted the order until now.

Also pinned here: a rejected delivery must create no check run and spawn no job (otherwise an
unsigned request can make the bot comment on an arbitrary repo), and a failure to write the
pending record must not stop the job - better a job that runs and might hang than a PR that is
silently never scanned.
"""

import hashlib
import hmac
import json
from pathlib import Path

import pytest

# See the note in tests/test_detonate_job.py: `brain.app` needs the Modal SDK, which these
# tests import inside a fixture, so without it they fail at run time instead of skipping.
pytest.importorskip("modal", reason="Modal SDK not installed; see requirements-dev.txt")

FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "webhook-secret"
CHECK_ID = 4242


def signed(body: bytes, secret: str = SECRET) -> dict[str, str]:
    mac = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "delivery-1",
        "X-Hub-Signature-256": f"sha256={mac}",
    }


def body(**overrides) -> bytes:
    data = json.loads((FIXTURES / "webhook_pr_opened.json").read_text())
    data.update(overrides)
    return json.dumps(data).encode()


class Recorder:
    """Records the order of every side effect, which is the thing under test."""

    def __init__(self) -> None:
        self.order: list[str] = []
        self.pending: dict = {}
        self.spawned: list = []
        self.fail_pending_write = False

    # --- the GitHub client ---
    def create_check_run(self, inst, owner, repo, sha, details_url=None):
        self.order.append("create_check_run")
        self.details_url = details_url
        return CHECK_ID

    # --- the pending_checks Dict ---
    def __setitem__(self, key, value):
        if self.fail_pending_write:
            raise RuntimeError("Modal Dict unavailable")
        self.order.append("record_pending")
        self.pending[key] = value

    # --- detonate_job ---
    def spawn(self, event, check_run_id):
        self.order.append("spawn")
        self.spawned.append((event, check_run_id))


@pytest.fixture
def handle(monkeypatch):
    import brain.app as app

    rec = Recorder()
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("ALLOWED_ACCOUNTS", "Demo-Org")
    monkeypatch.setattr(app, "github", lambda: rec)
    monkeypatch.setattr(app, "pending_checks", rec)
    monkeypatch.setattr(app, "detonate_job", rec)
    # One deduper per fixture, with per-instance state: class-level state here leaks between
    # tests and every delivery after the first is rejected as a duplicate.
    deduper = _MemoryDeduper()
    monkeypatch.setattr(app, "ModalDictDeduper", lambda: deduper)

    def run(b=None, headers=None):
        b = body() if b is None else b
        return app._handle(headers if headers is not None else signed(b), b)

    run.rec = rec
    return run


class _MemoryDeduper:
    def __init__(self) -> None:
        self.seen: set[str] = set()

    def first_delivery(self, delivery_id: str) -> bool:
        if delivery_id in self.seen:
            return False
        self.seen.add(delivery_id)
        return True


def test_the_pending_record_is_written_before_the_job_is_spawned(handle):
    """The ordering guarantee. A job that dies on cold start is only ever closed by the
    reconciler, and the reconciler only sees checks already in `pending_checks`."""
    resp = handle()

    assert resp.status_code == 202
    rec = handle.rec
    assert rec.order == ["create_check_run", "record_pending", "spawn"]
    assert rec.order.index("record_pending") < rec.order.index("spawn")
    assert list(rec.pending) == [f"check:{CHECK_ID}"]


def test_the_recorded_pending_check_is_complete_enough_to_reconcile(handle):
    """A record the reconciler cannot parse is as bad as no record: `reconcile` drops it."""
    from brain.reconcile import PendingCheck, reconcile

    handle()
    raw = handle.rec.pending[f"check:{CHECK_ID}"]

    check = PendingCheck(**raw)  # must not raise
    assert check.check_run_id == CHECK_ID
    assert check.started_at > 0
    actions = reconcile({check.key: raw}, _NoGitHub(), now=check.started_at + 1)
    assert actions == {check.key: "waiting"}, "a fresh record must not be reconciled as dropped"


class _NoGitHub:
    def get_check_run(self, *a):
        raise AssertionError("should not be called for a fresh record")


def test_an_unsigned_delivery_creates_no_check_and_spawns_nothing(handle):
    """Without this, a forged request could make the bot act on an arbitrary repo."""
    b = body()
    bad = signed(b, secret="wrong-secret")

    resp = handle(b, bad)

    assert resp.status_code != 202
    assert handle.rec.order == [], "acted on an unverified delivery"
    assert handle.rec.spawned == []


def test_a_repo_outside_the_allowlist_spawns_nothing(handle, monkeypatch):
    monkeypatch.setenv("ALLOWED_ACCOUNTS", "someone-else")

    resp = handle()

    assert resp.status_code != 202
    assert handle.rec.order == []


def test_a_failed_pending_write_still_spawns_the_job(handle):
    """Deliberate tradeoff: a job that runs and might hang beats a PR silently never scanned.
    The reconciler is the backstop, and it is best-effort by design here."""
    handle.rec.fail_pending_write = True

    resp = handle()

    assert resp.status_code == 202
    assert handle.rec.order == ["create_check_run", "spawn"]
    assert handle.rec.spawned, "a Modal Dict blip silently dropped the PR"


def test_the_check_links_back_to_the_pull_request(handle):
    """Without details_url GitHub links "Details" at the App's homepage, which is useless to a
    reviewer looking at a blocked PR."""
    handle()

    assert handle.rec.details_url == "https://github.com/demo-org/demo-repo/pull/7"


def test_the_spawned_job_gets_the_same_check_run_id_it_must_complete(handle):
    handle()

    event, check_run_id = handle.rec.spawned[0]
    assert check_run_id == CHECK_ID
    assert event.head_sha == "0123456789abcdef0123456789abcdef01234567"
