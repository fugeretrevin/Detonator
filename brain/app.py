"""Modal app: GitHub webhook endpoint + async detonation job.

Deploy from the repo root: `modal deploy -m brain.app`
"""

import asyncio
import functools
import logging
import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import modal
from fastapi import Request
from fastapi.responses import JSONResponse

from brain import prompt_guard as pg
from brain.chamber_client import chamber_client_from_env
from brain.enrich import github_meta_cidrs
from brain.github_client import GitHubClient, PrMetadata
from brain.intent import PredictionOutcome, predict
from brain.llm import LlmOutcome, llm_client_from_env
from brain.pipeline import (
    PRIVATE_REPO_SUMMARY,
    PRIVATE_REPO_TITLE,
    analyze,
    detonate_request,
)
from brain.report import render_line_comment, with_run_history
from brain.runlog import build_record
from brain.webhook import PullRequestEvent, handle_webhook, parse_allowed_accounts
from shared.contract import DetonateRequest, DetonateResult

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

# Llama Prompt Guard 2 on CPU. The weights are baked in at build time; HF_TOKEN is only in
# that build step, never in the running function.
guard_image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("torch==2.5.1", index_url="https://download.pytorch.org/whl/cpu")
    .pip_install(
        "transformers==4.46.3",
        "huggingface_hub[cli]==0.26.2",
        "sentencepiece==0.2.0",
        "protobuf==5.28.3",
    )  # fmt: skip
    .pip_install_from_requirements(str(ROOT / "brain/requirements.txt"))
    .run_commands(
        f"huggingface-cli download {pg.MODEL_ID} --local-dir {pg.MODEL_DIR}",
        secrets=[modal.Secret.from_name("huggingface")],
    )
    .add_local_python_source("shared", "brain")
)

SECRETS = [
    modal.Secret.from_name("github-app"),
    modal.Secret.from_name("detonator-config"),
    modal.Secret.from_name("llama"),
    modal.Secret.from_name("chamber"),
]

deliveries = modal.Dict.from_name("pr-detonator-deliveries", create_if_missing=True)
# Chamber health history, written every 10 minutes (HARDENING_PLAN P0.5).
health_log = modal.Dict.from_name("pr-detonator-health", create_if_missing=True)
HEALTH_HISTORY = 144  # 24 h at one check per 10 min
# Per-run summaries for the dashboard (HARDENING_PLAN P1.6).
run_log = modal.Dict.from_name("pr-detonator-runs", create_if_missing=True)
RUN_LOG_HISTORY = 200
# Base-branch detonation results, cached by SHA for differential detonation (P2.1).
base_cache = modal.Dict.from_name("pr-detonator-base-cache", create_if_missing=True)


class ModalDictDeduper:
    def first_delivery(self, delivery_id: str) -> bool:
        return deliveries.put(delivery_id, True, skip_if_exists=True)


@functools.cache
def _new_package_resolver():
    from brain.newpkg import registry_resolver

    return registry_resolver()


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
        event.installation_id,
        event.owner,
        event.repo,
        event.head_sha,
        details_url=f"https://github.com/{event.owner}/{event.repo}/pull/{event.number}",
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
        chamber = chamber_client_from_env()
        private_token = None
        if event.repo_private and getattr(chamber, "tls", False):
            # Read-only, this repo only; used by git on the Chamber host, never the sandbox.
            private_token = gh.repo_read_token(event.installation_id, event.repo)
    except Exception as exc:
        summary = f"Detonator setup error (`{type(exc).__name__}`), job `{job_id}`."
        gh.complete_check_run(*loc, check_run_id, "failure", "Could not verify this PR", summary)
        raise
    request = detonate_request(event, job_id, private_token=private_token)
    if request is None:
        logger.info(
            "job=%s %s/%s#%s private repo: not detonated",
            job_id,
            event.owner,
            event.repo,
            event.number,
        )
        gh.complete_check_run(
            *loc, check_run_id, "failure", PRIVATE_REPO_TITLE, PRIVATE_REPO_SUMMARY
        )
        return
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        files = gh.list_pr_files(*loc, event.number)
        metadata = gh.get_pr_metadata(*loc, event.number, files=files)
        diff = gh.get_pr_diff(*loc, event.number)
        # The model commits to its prediction while the sandbox runs, before any telemetry.
        prediction_future = pool.submit(_predict, metadata)
        guard_future = pool.submit(_guard, metadata, diff)
        result = chamber.detonate(request)
        # Dependency-affecting PRs: detonate the base too (cached by SHA) and report the delta.
        base_result = _base_detonation(chamber, event, metadata) if event.base_sha else None
        prediction = prediction_future.result(timeout=150)
        try:
            guard = guard_future.result(timeout=60)
        except TimeoutError:
            guard = pg.GuardOutcome(error="timeout")
        analysis = analyze(
            result,
            metadata,
            diff,
            _llm_analyzer(),
            job_id=job_id,
            prediction=prediction,
            allowed_cidrs=github_meta_cidrs(),
            files=files,
            guard=guard,
            base_result=base_result,
            new_package_resolver=_new_package_resolver(),
            investigator=_investigate,
        )
        final = analysis.final
        logger.info(
            "job=%s %s/%s#%s -> %s (rules=%s llm=%s llm_error=%s unexplained=%d cleared=%d "
            "prediction_error=%s)",
            job_id,
            event.owner,
            event.repo,
            event.number,
            final.conclusion,
            final.rule_level.name,
            final.llm_level.name if final.llm_level else None,
            analysis.llm.error,
            len(analysis.contract.unexplained),
            len(analysis.cleared),
            prediction.error,
        )
        gh.complete_check_run(
            *loc, check_run_id, final.conclusion, f"PR Detonator: {final.title}", analysis.report
        )
    except Exception as exc:
        # Never leave the check hanging; fail closed (neutral would pass branch protection).
        gh.complete_check_run(
            *loc,
            check_run_id,
            "failure",
            "Could not verify this PR",
            f"Detonator internal error (`{type(exc).__name__}`), job `{job_id}`.",
        )
        raise
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    # The check already carries the verdict; a failed comment must not overwrite it.
    try:
        title = analysis.final.title
        gh.upsert_comment(*loc, event.number, analysis.report,
                          merge=lambda prev: with_run_history(analysis.report, prev,
                                                              event.head_sha, title))  # fmt: skip
    except Exception:
        logger.exception("job=%s failed to post PR comment", job_id)

    if analysis.final.title == "Blocked" and analysis.guilty:
        comments = [
            {"path": g.path, "line": g.line,
             "body": render_line_comment(g, i, analysis.llm, analysis.result)}
            for i, g in enumerate(analysis.guilty)
            if g.in_diff  # lines inside a dependency's file aren't in the diff: report only
        ]  # fmt: skip
        try:
            if comments:  # GitHub rejects an empty review
                gh.create_review(*loc, event.number, event.head_sha, comments)
        except Exception:
            logger.exception("job=%s failed to post guilty-line review", job_id)

    # Run log for the dashboard (best effort; a logging failure must not fail the job).
    try:
        import datetime

        ts = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M")
        rec = build_record(event, analysis, job_id, ts)
        run_log["records"] = ((run_log.get("records") or [])[-(RUN_LOG_HISTORY - 1) :]) + [rec]
    except Exception:
        logger.exception("job=%s failed to write run log", job_id)


@app.cls(image=guard_image, cpu=2.0, memory=2048, scaledown_window=300, timeout=120)
class PromptGuard:
    @modal.enter()
    def load(self) -> None:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        torch.set_num_threads(2)
        self.tokenizer = AutoTokenizer.from_pretrained(pg.MODEL_DIR)
        self.model = AutoModelForSequenceClassification.from_pretrained(pg.MODEL_DIR).eval()
        label = self.model.config.id2label.get(pg.MALICIOUS_LABEL, "")
        if label != "LABEL_1":
            raise RuntimeError(f"unexpected Prompt Guard labels: {self.model.config.id2label}")

    @modal.method()
    def scan(self, texts: dict[str, str]) -> pg.GuardOutcome:
        return pg.scan_texts(self.tokenizer, self.model, texts)

    @modal.method()
    def reference(self, texts: list[str]) -> list[dict]:
        """Diagnostics: Hugging Face's own pipeline + tokens, to check scan_texts against."""
        from transformers import pipeline

        clf = pipeline("text-classification", model=self.model, tokenizer=self.tokenizer,
                       truncation=True, max_length=pg.WINDOW_TOKENS, top_k=None)  # fmt: skip
        out = []
        for text, scores in zip(texts, clf(texts), strict=True):
            ids = self.tokenizer(text, add_special_tokens=False)["input_ids"]
            out.append({"scores": scores,
                        "tokens": self.tokenizer.convert_ids_to_tokens(ids)[:12]})  # fmt: skip
        return out


@app.function(image=image)
@modal.asgi_app()
def dashboard():
    """Read-only public page: recent runs, verdict tally, behavior atlas. No inputs accepted."""
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse

    from brain.runlog import render_dashboard

    web = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @web.get("/", response_class=HTMLResponse)
    def index() -> str:
        records = run_log.get("records") or []
        return render_dashboard(records)

    return web


@app.function(image=image, secrets=SECRETS, schedule=modal.Period(minutes=10), timeout=60)
def chamber_health() -> dict:
    """Is the Chamber up? Recorded so an outage during judging is visible, not silent."""
    import datetime

    try:
        status = chamber_client_from_env().health()
    except Exception as exc:  # missing secret etc.: still record it
        status = {"ok": False, "detail": f"check failed ({type(exc).__name__})"}
    status["ts"] = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
    history = (health_log.get("history") or [])[-(HEALTH_HISTORY - 1) :] + [status]
    health_log["latest"] = status
    health_log["history"] = history
    if not status["ok"]:
        logger.warning("chamber health: DOWN (%s)", status["detail"])
    return status


def _guard(metadata: PrMetadata, diff: str) -> pg.GuardOutcome:
    try:
        return PromptGuard().scan.remote(pg.guard_inputs(metadata, diff))
    except Exception as exc:  # screening is advisory: never fail the job on it
        logger.exception("prompt guard failed")
        return pg.GuardOutcome(error=type(exc).__name__)


_HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _base_detonation(chamber, event: PullRequestEvent, metadata: PrMetadata):
    """Detonate the PR's base commit for differential reporting. Best effort and cached by
    SHA; any failure returns None (the PR is still judged on its own behavior). Only for
    public, dependency-affecting PRs with a valid, different base SHA."""
    if event.repo_private or not _HEX40.match(event.base_sha or ""):
        return None
    if event.base_sha == event.head_sha:
        return None
    if not (metadata.package_json_changed or metadata.lockfile_changed):
        return None  # nothing dependency-related changed: a base run would add no signal
    key = f"{event.owner}/{event.repo}@{event.base_sha}"
    try:
        cached = base_cache.get(key)
        if cached:
            return DetonateResult.model_validate_json(cached)
        base_url = f"https://github.com/{event.owner}/{event.repo}.git"
        req = DetonateRequest(job_id=str(uuid.uuid4()), clone_url=base_url,
                              head_sha=event.base_sha, clone_token=None)  # fmt: skip
        result = chamber.detonate(req)
        base_cache[key] = result.model_dump_json()
        return result
    except Exception:
        logger.exception("base detonation failed for %s", key)
        return None


def _investigate(hits, result):
    """Triage a ⚠️ PR with the investigator agent. Best effort: on any failure the verdict
    stands as it was (the agent can only ever escalate)."""
    from brain.investigator import investigate

    try:
        return investigate(llm_client_from_env(), hits, result)
    except Exception:
        logger.exception("investigator agent failed")
        return None


def _predict(metadata: PrMetadata) -> PredictionOutcome:
    try:
        return predict(llm_client_from_env(), metadata)
    except KeyError as exc:
        return PredictionOutcome(os.environ.get("LLAMA_MODEL", "llm"), error=f"{exc.args[0]} unset")


def _llm_analyzer():
    try:
        return llm_client_from_env().analyze
    except KeyError as exc:  # secret missing: degrade to a rules-only verdict
        missing = exc.args[0]
        return lambda *_: LlmOutcome(os.environ.get("LLAMA_MODEL", "llm"), error=f"{missing} unset")
