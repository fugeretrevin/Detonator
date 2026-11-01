"""Modal app: GitHub webhook endpoint + async detonation job.

Deploy from the repo root: `modal deploy -m brain.app`
"""

import asyncio
import functools
import logging
import os
import uuid
from pathlib import Path

import modal
from fastapi import Request
from fastapi.responses import JSONResponse

from brain.chamber_client import chamber_client_from_env
from brain.enrich import github_meta_cidrs
from brain.github_client import GitHubClient
from brain.llm import LlmOutcome, llm_client_from_env
from brain.pipeline import analyze
from brain.webhook import PullRequestEvent, handle_webhook, parse_allowed_accounts
from shared.contract import DetonateRequest

ROOT = Path(__file__).resolve().parent.parent

# Modal captures stdout/stderr; make INFO-level webhook decisions visible in its logs.
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", force=True)
logger = logging.getLogger("brain.app")

app = modal.App("pr-detonator")

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install_from_requirements(str(ROOT / "brain/requirements.txt"))
    .add_local_python_source("shared", "brain")
    .add_local_dir(str(ROOT / "tests/fixtures"), "/root/fixtures")
)

# Add modal.Secret.from_name("chamber") here once B8 is wired (CHAMBER_MODE=http).
SECRETS = [
    modal.Secret.from_name("github-app"),
    modal.Secret.from_name("detonator-config"),
    modal.Secret.from_name("llama"),
]

deliveries = modal.Dict.from_name("pr-detonator-deliveries", create_if_missing=True)


class ModalDictDeduper:
    def first_delivery(self, delivery_id: str) -> bool:
        return deliveries.put(delivery_id, True, skip_if_exists=True)


@functools.cache
def github() -> GitHubClient:
    # Cached per container so installation tokens are reused across warm requests.
    return GitHubClient(os.environ["GITHUB_APP_ID"], os.environ["GITHUB_PRIVATE_KEY"])


def _handle(headers: dict[str, str], body: bytes) -> JSONResponse:
    decision = handle_webhook(
        headers,
        body,
        secret=os.environ["GITHUB_WEBHOOK_SECRET"],
        allowed_accounts=parse_allowed_accounts(os.environ.get("ALLOWED_ACCOUNTS")),
        deduper=ModalDictDeduper(),
    )
    if not decision.accepted:
        return JSONResponse({"status": decision.reason}, status_code=decision.status_code)

    event = decision.event
    check_run_id = github().create_check_run(
        event.installation_id, event.owner, event.repo, event.head_sha
    )
    detonate_job.spawn(event, check_run_id)
    return JSONResponse({"status": "accepted", "check_run_id": check_run_id}, status_code=202)


@app.function(image=image, secrets=SECRETS)
@modal.fastapi_endpoint(method="POST")
async def webhook(request: Request) -> JSONResponse:
    body = await request.body()  # raw bytes: needed for signature verification
    # Blocking GitHub/Modal calls run off the event loop.
    return await asyncio.to_thread(_handle, dict(request.headers), body)


@app.function(image=image, secrets=SECRETS, timeout=600)
def detonate_job(event: PullRequestEvent, check_run_id: int) -> None:
    gh = github()
    loc = (event.installation_id, event.owner, event.repo)
    job_id = str(uuid.uuid4())
    try:
        metadata = gh.get_pr_metadata(*loc, event.number)
        diff = gh.get_pr_diff(*loc, event.number)
        result = chamber_client_from_env().detonate(
            DetonateRequest(
                job_id=job_id,
                clone_url=event.head_clone_url,
                head_sha=event.head_sha,
                clone_token=gh.installation_token(event.installation_id),
            )
        )
        analysis = analyze(
            result,
            metadata,
            diff,
            _llm_analyzer(),
            job_id=job_id,
            allowed_cidrs=github_meta_cidrs(),
        )
        final = analysis.final
        logger.info(
            "job=%s %s/%s#%s -> %s (rules=%s llm=%s llm_error=%s)",
            job_id,
            event.owner,
            event.repo,
            event.number,
            final.conclusion,
            final.rule_level.name,
            final.llm_level.name if final.llm_level else None,
            analysis.llm.error,
        )
        gh.complete_check_run(
            *loc, check_run_id, final.conclusion, f"PR Detonator: {final.title}", analysis.report
        )
    except Exception as exc:
        # Never leave the check hanging, and never report success on failure.
        gh.complete_check_run(
            *loc,
            check_run_id,
            "neutral",
            "Could not verify this PR",
            f"Detonator internal error (`{type(exc).__name__}`), job `{job_id}`.",
        )
        raise

    # The check already carries the verdict; a failed comment must not overwrite it.
    try:
        gh.post_comment(*loc, event.number, analysis.report)
    except Exception:
        logger.exception("job=%s failed to post PR comment", job_id)


def _llm_analyzer():
    try:
        return llm_client_from_env().analyze
    except KeyError as exc:  # secret missing: degrade to a rules-only verdict
        missing = exc.args[0]
        return lambda *_: LlmOutcome(os.environ.get("LLAMA_MODEL", "llm"), error=f"{missing} unset")
