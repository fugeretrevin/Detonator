"""GitHub webhook verification, event parsing, allowlist and dedupe.

Kept free of Modal/FastAPI so the whole accept/reject decision is unit-testable.
"""

import hashlib
import hmac
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

HANDLED_ACTIONS = frozenset({"opened", "synchronize", "reopened"})

logger = logging.getLogger(__name__)


def verify_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    if not secret or not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def parse_allowed_accounts(raw: str | None) -> frozenset[str]:
    """Comma-separated logins -> lowercase set. Empty means nothing is allowed."""
    return frozenset(part.strip().lower() for part in (raw or "").split(",") if part.strip())


@dataclass(frozen=True)
class PullRequestEvent:
    delivery_id: str
    action: str
    installation_id: int
    account_login: str
    owner: str
    repo: str
    number: int
    head_sha: str
    head_clone_url: str
    is_fork: bool
    repo_private: bool = True  # fail closed if GitHub omits the flag
    title: str = ""  # PR title (untrusted; for the dashboard, escaped on render)
    base_sha: str = ""  # the PR's base commit, for differential detonation


def account_login(payload: dict) -> str | None:
    # pull_request payloads carry only installation.id/node_id (no account), so the base
    # repo owner is the signal for "whose installation is this".
    owner = ((payload.get("repository") or {}).get("owner")) or {}
    return owner.get("login")


def parse_pull_request_event(delivery_id: str, payload: dict) -> PullRequestEvent:
    pr = payload["pull_request"]
    base_repo = payload["repository"]
    # head.repo is null when a fork has been deleted; fall back to the base repo URL.
    head_repo = pr["head"].get("repo") or base_repo
    return PullRequestEvent(
        delivery_id=delivery_id,
        action=payload["action"],
        installation_id=int(payload["installation"]["id"]),
        account_login=account_login(payload) or "",
        owner=base_repo["owner"]["login"],
        repo=base_repo["name"],
        number=int(pr["number"]),
        head_sha=pr["head"]["sha"],
        head_clone_url=head_repo["clone_url"],
        is_fork=head_repo["full_name"] != base_repo["full_name"],
        repo_private=base_repo.get("private") is not False or head_repo.get("private") is True,
        title=(pr.get("title") or "")[:200],
        base_sha=(pr.get("base") or {}).get("sha") or "",
    )


class Deduper(Protocol):
    def first_delivery(self, delivery_id: str) -> bool:
        """Record the delivery; return True only the first time it is seen."""
        ...


@dataclass(frozen=True)
class Decision:
    status_code: int
    reason: str
    event: PullRequestEvent | None = None

    @property
    def accepted(self) -> bool:
        return self.event is not None


def handle_webhook(
    headers: Mapping[str, str],
    body: bytes,
    *,
    secret: str,
    allowed_accounts: frozenset[str],
    deduper: Deduper,
) -> Decision:
    h = {k.lower(): v for k, v in headers.items()}
    delivery_id = h.get("x-github-delivery")

    def reject(status_code: int, reason: str) -> Decision:
        logger.info("webhook delivery=%s rejected: %s %s", delivery_id, status_code, reason)
        return Decision(status_code, reason)

    if not verify_signature(secret, body, h.get("x-hub-signature-256")):
        return reject(401, "bad signature")

    if h.get("x-github-event") != "pull_request":
        return reject(200, f"ignored event {h.get('x-github-event')!r}")

    try:
        payload = json.loads(body)
    except ValueError:
        return reject(400, "invalid json")

    action = payload.get("action")
    if action not in HANDLED_ACTIONS:
        return reject(200, f"ignored action {action!r}")

    login = account_login(payload)
    if not login or login.lower() not in allowed_accounts:
        return reject(
            200, f"account {login!r} not allowlisted (allowed: {sorted(allowed_accounts)})"
        )

    if not delivery_id:
        return reject(400, "missing delivery id")
    if not deduper.first_delivery(delivery_id):
        return reject(200, "duplicate delivery")

    try:
        event = parse_pull_request_event(delivery_id, payload)
    except (KeyError, TypeError, ValueError) as exc:
        return reject(400, f"malformed pull_request payload ({type(exc).__name__}: {exc})")
    logger.info(
        "webhook delivery=%s accepted: %s/%s#%s %s head=%s",
        delivery_id,
        event.owner,
        event.repo,
        event.number,
        event.action,
        event.head_sha[:8],
    )
    return Decision(202, "accepted", event)
