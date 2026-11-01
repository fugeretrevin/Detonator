import hashlib
import hmac
import json
import logging
from pathlib import Path

import pytest

from brain.webhook import handle_webhook, parse_allowed_accounts, verify_signature

FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "webhook-secret"
ALLOWED = parse_allowed_accounts("Demo-Org")


class MemoryDeduper:
    def __init__(self) -> None:
        self.seen: set[str] = set()

    def first_delivery(self, delivery_id: str) -> bool:
        if delivery_id in self.seen:
            return False
        self.seen.add(delivery_id)
        return True


def sig(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def payload(**overrides) -> dict:
    data = json.loads((FIXTURES / "webhook_pr_opened.json").read_text())
    data.update(overrides)
    return data


def call(body: bytes, *, event="pull_request", delivery="d-1", signature=None, deduper=None):
    headers = {
        "X-GitHub-Event": event,
        "X-GitHub-Delivery": delivery,
        "X-Hub-Signature-256": signature if signature is not None else sig(body),
    }
    return handle_webhook(
        headers,
        body,
        secret=SECRET,
        allowed_accounts=ALLOWED,
        deduper=deduper or MemoryDeduper(),
    )


def test_valid_pr_opened_is_accepted():
    decision = call(json.dumps(payload()).encode())
    assert decision.status_code == 202
    event = decision.event
    assert event.owner == "demo-org" and event.repo == "demo-repo" and event.number == 7
    assert event.installation_id == 12345678
    assert event.head_sha == "0123456789abcdef0123456789abcdef01234567"
    assert event.head_clone_url == "https://github.com/demo-org/demo-repo.git"
    assert event.is_fork is False


def test_tampered_body_rejected():
    body = json.dumps(payload()).encode()
    decision = call(body + b" ", signature=sig(body))
    assert decision.status_code == 401
    assert decision.event is None


@pytest.mark.parametrize("header", ["", "sha256=deadbeef", "sha1=abc", sig(b"x", "wrong")])
def test_bad_signatures_rejected(header):
    assert call(json.dumps(payload()).encode(), signature=header).status_code == 401


def test_verify_signature_requires_secret():
    assert not verify_signature("", b"body", sig(b"body", ""))


def test_non_pull_request_event_noops():
    decision = call(b'{"zen": "hi"}', event="ping")
    assert decision.status_code == 200 and not decision.accepted


@pytest.mark.parametrize("action", ["closed", "labeled", "edited"])
def test_irrelevant_action_noops(action):
    decision = call(json.dumps(payload(action=action)).encode())
    assert decision.status_code == 200 and not decision.accepted


@pytest.mark.parametrize("action", ["synchronize", "reopened"])
def test_handled_actions_accepted(action):
    assert call(json.dumps(payload(action=action)).encode()).accepted


def test_non_allowlisted_account_noops():
    data = payload()
    data["repository"]["owner"]["login"] = "random-user"
    decision = call(json.dumps(data).encode())
    assert decision.status_code == 200 and not decision.accepted


def test_fixture_installation_matches_real_shape():
    assert set(payload()["installation"]) == {"id", "node_id"}


def test_allowlist_uses_repository_owner_not_installation_account():
    data = payload()
    data["installation"]["account"] = {"login": "someone-else"}
    data["repository"]["owner"]["login"] = "random-user"
    assert not call(json.dumps(data).encode()).accepted


@pytest.mark.parametrize(
    "kwargs, data, expected",
    [
        ({"event": "ping"}, None, "ignored event 'ping'"),
        ({}, {"action": "closed"}, "ignored action 'closed'"),
        ({}, {"repository": {"owner": {"login": "random-user"}}}, "'random-user' not allowlisted"),
    ],
)
def test_early_returns_are_logged(caplog, kwargs, data, expected):
    body = payload()
    body.update(data or {})
    with caplog.at_level(logging.INFO, logger="brain.webhook"):
        call(json.dumps(body).encode(), **kwargs)
    assert expected in caplog.text and "delivery=d-1" in caplog.text


def test_duplicate_delivery_is_logged(caplog):
    body = json.dumps(payload()).encode()
    deduper = MemoryDeduper()
    call(body, deduper=deduper)
    with caplog.at_level(logging.INFO, logger="brain.webhook"):
        call(body, deduper=deduper)
    assert "duplicate delivery" in caplog.text


def test_empty_allowlist_denies_everything():
    body = json.dumps(payload()).encode()
    decision = handle_webhook(
        {
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "d",
            "X-Hub-Signature-256": sig(body),
        },
        body,
        secret=SECRET,
        allowed_accounts=parse_allowed_accounts(""),
        deduper=MemoryDeduper(),
    )
    assert not decision.accepted


def test_duplicate_delivery_ignored():
    body = json.dumps(payload()).encode()
    deduper = MemoryDeduper()
    assert call(body, delivery="same", deduper=deduper).accepted
    second = call(body, delivery="same", deduper=deduper)
    assert second.status_code == 200 and not second.accepted


def test_fork_detected_and_deleted_fork_falls_back():
    data = payload()
    data["pull_request"]["head"]["repo"] = {
        "full_name": "attacker/demo-repo",
        "clone_url": "https://github.com/attacker/demo-repo.git",
    }
    assert call(json.dumps(data).encode()).event.is_fork

    data["pull_request"]["head"]["repo"] = None
    event = call(json.dumps(data).encode(), delivery="d-2").event
    assert event.head_clone_url == "https://github.com/demo-org/demo-repo.git"


def test_malformed_json_is_400():
    assert call(b"not json").status_code == 400
