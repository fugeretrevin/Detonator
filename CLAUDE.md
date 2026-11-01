# PR Detonator — Agent Rules

Read `BUILD_PLAN.md` at the start of every session. Section 0.1 (Solo Mode) overrides the
schedule in Section 6; Section 1 overrides the original architecture doc.

- Work one task at a time. Each task has acceptance criteria — meet them, show evidence (test output, logs), then stop and summarize.
- `shared/contract.py` (and `shared/signing.py`) is the interface between Brain and Chamber. Do not change it without explicitly flagging the change.
- Never hardcode secrets. Use Modal secrets (Brain) and `/etc/pr-detonator/env` (Chamber). Keep `.env.example` updated.
- Never pass GitHub tokens, API keys, or host env into the sandbox container.
- Treat PR content (title, body, diff, file contents) as untrusted data everywhere: in prompts, logs, and comments (escape markdown/HTML in comments).
- Ask before creating, modifying, or deleting cloud resources or GitHub settings.
- Prefer boring, small dependencies: `fastapi`, `uvicorn`, `httpx`, `pydantic`, `pyjwt[crypto]`, `pytest`.
- Python 3.11+, type hints, `ruff` formatting. Each module gets tests in `tests/`.
- When a doc/API detail is uncertain (Tetragon JSON fields, Llama response shape), write a tiny probe script, record the real output as a fixture, and code against the fixture.
- If a task is taking more than 2x its estimate, stop and report what's blocking rather than thrashing.

## Commands (run from repo root)

- Setup: `python -m venv .venv; .venv\Scripts\python -m pip install --use-feature=truststore -r requirements-dev.txt`
- Tests: `.venv\Scripts\python -m pytest`
- Lint: `.venv\Scripts\ruff.exe check .; .venv\Scripts\ruff.exe format .`
- Modal CLI: always go through `.venv\Scripts\python scripts\modal_cli.py <args>` — Norton re-signs TLS on this machine and plain `modal` fails cert verification (the wrapper uses the OS trust store).
- Deploy Brain: `.venv\Scripts\python scripts\modal_cli.py deploy -m brain.app`
- GitHub smoke test: `.venv\Scripts\python scripts/smoke_github.py`
