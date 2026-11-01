"""GitHub App auth, check runs, PR diff/metadata and comments (BUILD_PLAN A2)."""

import re
import time
from collections.abc import Callable
from datetime import datetime
from typing import Literal

import httpx
import jwt
from pydantic import BaseModel

API_URL = "https://api.github.com"
CHECK_NAME = "PR Detonator"
COMMENT_MARKER = "<!-- pr-detonator -->"
MAX_DIFF_CHARS = 30_000
MAX_BODY_CHARS = 2_000
MAX_SUMMARY_CHARS = 65_000
TOKEN_REFRESH_MARGIN_S = 300

LOCKFILES = frozenset({"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"})
SCRIPT_KEYS = ('"scripts"', '"preinstall"', '"install"', '"postinstall"', '"prepare"')

Conclusion = Literal["success", "failure", "neutral"]


def load_private_key(raw: str) -> str:
    """Accept a PEM whose newlines were escaped as literal \\n (common in env vars)."""
    return raw.replace("\\n", "\n").strip() + "\n"


def truncate(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit] + f"\n\n[... truncated {len(text) - limit} chars ...]", True


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


class ChangedFile(BaseModel):
    filename: str
    status: str
    patch: str | None = None


class PrMetadata(BaseModel):
    title: str
    body: str
    author: str
    changed_files: list[str]
    package_json_changed: bool
    scripts_changed: bool
    lockfile_changed: bool
    added_dependencies: list[str] = []


# `+    "esbuild": "^0.25.0",` (also scoped names, ranges, tags, npm: aliases, git/https specs)
_DEP_LINE_RE = re.compile(
    r'^\+\s*"(@?[a-z0-9][\w.-]*(?:/[\w.-]+)?)"\s*:\s*"([\^~<>=*\dvx]|latest|next|npm:|git|https?:)'
)
_NOT_DEPS = frozenset({"name", "version", "main", "type", "license", "node", "npm"})


def added_dependencies(files: list[ChangedFile]) -> list[str]:
    """Dependency names added in package.json patches (names only, never script bodies)."""
    names: list[str] = []
    for f in files:
        if _basename(f.filename) != "package.json" or not f.patch:
            continue
        for line in f.patch.splitlines():
            m = _DEP_LINE_RE.match(line)
            if m and m.group(1) not in _NOT_DEPS and m.group(1) not in names:
                names.append(m.group(1))
    return names[:30]


def scripts_changed(files: list[ChangedFile]) -> bool:
    """Heuristic: a package.json patch adds/removes a line touching scripts or a lifecycle hook."""
    for f in files:
        if _basename(f.filename) != "package.json" or not f.patch:
            continue
        for line in f.patch.splitlines():
            if line[:1] in "+-" and not line.startswith(("+++", "---")):
                if any(key in line for key in SCRIPT_KEYS):
                    return True
    return False


class GitHubClient:
    def __init__(
        self,
        app_id: str,
        private_key: str,
        *,
        http: httpx.Client | None = None,
        api_url: str = API_URL,
    ) -> None:
        self.app_id = str(app_id)
        self._private_key = load_private_key(private_key)
        self._http = http or httpx.Client(base_url=api_url, timeout=15.0)
        self._http.headers.update(
            {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        )
        self._tokens: dict[int, tuple[str, float]] = {}

    # --- auth ---

    def app_jwt(self, now: float | None = None) -> str:
        issued = int(time.time() if now is None else now)
        claims = {"iat": issued - 60, "exp": issued + 540, "iss": self.app_id}
        return jwt.encode(claims, self._private_key, algorithm="RS256")

    def installation_token(self, installation_id: int) -> str:
        cached = self._tokens.get(installation_id)
        if cached and cached[1] - time.time() > TOKEN_REFRESH_MARGIN_S:
            return cached[0]
        resp = self._http.post(
            f"/app/installations/{installation_id}/access_tokens",
            headers={"Authorization": f"Bearer {self.app_jwt()}"},
        )
        resp.raise_for_status()
        data = resp.json()
        expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")).timestamp()
        self._tokens[installation_id] = (data["token"], expires_at)
        return data["token"]

    def repo_read_token(self, installation_id: int, repo: str) -> str:
        """A fresh token that can only read this one repository's contents (for cloning a
        private repo on the Chamber host; never cached, never reaches the sandbox)."""
        resp = self._http.post(
            f"/app/installations/{installation_id}/access_tokens",
            headers={"Authorization": f"Bearer {self.app_jwt()}"},
            json={"repositories": [repo], "permissions": {"contents": "read"}},
        )
        resp.raise_for_status()
        return resp.json()["token"]

    def _request(self, installation_id: int, method: str, path: str, **kwargs) -> httpx.Response:
        headers = dict(kwargs.pop("headers", None) or {})
        headers["Authorization"] = f"token {self.installation_token(installation_id)}"
        resp = self._http.request(method, path, headers=headers, **kwargs)
        resp.raise_for_status()
        return resp

    # --- check runs ---

    def create_check_run(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        head_sha: str,
        details_url: str | None = None,
    ) -> int:
        # Without details_url, GitHub links "Details" to the App's homepage.
        extra = {"details_url": details_url} if details_url else {}
        resp = self._request(
            installation_id,
            "POST",
            f"/repos/{owner}/{repo}/check-runs",
            json={
                "name": CHECK_NAME,
                **extra,
                "head_sha": head_sha,
                "status": "in_progress",
                "output": {
                    "title": "Detonating in sandbox...",
                    "summary": "Running install hooks under eBPF tracing.",
                },
            },
        )
        return int(resp.json()["id"])

    def complete_check_run(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        check_run_id: int,
        conclusion: Conclusion,
        title: str,
        summary: str,
    ) -> None:
        summary, _ = truncate(summary, MAX_SUMMARY_CHARS)
        self._request(
            installation_id,
            "PATCH",
            f"/repos/{owner}/{repo}/check-runs/{check_run_id}",
            json={
                "status": "completed",
                "conclusion": conclusion,
                "output": {"title": title[:255], "summary": summary},
            },
        )

    # --- pull request data ---

    def get_pr_diff(self, installation_id: int, owner: str, repo: str, number: int) -> str:
        resp = self._request(
            installation_id,
            "GET",
            f"/repos/{owner}/{repo}/pulls/{number}",
            headers={"Accept": "application/vnd.github.diff"},
        )
        diff, _ = truncate(resp.text, MAX_DIFF_CHARS)
        return diff

    def list_pr_files(
        self, installation_id: int, owner: str, repo: str, number: int
    ) -> list[ChangedFile]:
        files: list[ChangedFile] = []
        page = 1
        while True:
            resp = self._request(
                installation_id,
                "GET",
                f"/repos/{owner}/{repo}/pulls/{number}/files",
                params={"per_page": 100, "page": page},
            )
            batch = resp.json()
            files.extend(ChangedFile.model_validate(item) for item in batch)
            if len(batch) < 100 or page >= 30:  # GitHub caps this endpoint at 3000 files
                return files
            page += 1

    def get_pr_metadata(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        number: int,
        files: list[ChangedFile] | None = None,
    ) -> PrMetadata:
        pr = self._request(installation_id, "GET", f"/repos/{owner}/{repo}/pulls/{number}").json()
        if files is None:
            files = self.list_pr_files(installation_id, owner, repo, number)
        body, _ = truncate(pr.get("body") or "", MAX_BODY_CHARS)
        names = [f.filename for f in files]
        return PrMetadata(
            title=pr.get("title") or "",
            body=body,
            author=(pr.get("user") or {}).get("login", ""),
            changed_files=names,
            package_json_changed=any(_basename(n) == "package.json" for n in names),
            scripts_changed=scripts_changed(files),
            lockfile_changed=any(_basename(n) in LOCKFILES for n in names),
            added_dependencies=added_dependencies(files),
        )

    # --- comments ---

    def post_comment(
        self, installation_id: int, owner: str, repo: str, number: int, body: str
    ) -> int:
        if COMMENT_MARKER not in body:
            body = f"{body}\n\n{COMMENT_MARKER}"
        resp = self._request(
            installation_id,
            "POST",
            f"/repos/{owner}/{repo}/issues/{number}/comments",
            json={"body": body},
        )
        return int(resp.json()["id"])

    def upsert_comment(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        number: int,
        body: str,
        merge: Callable[[str | None], str] | None = None,
    ) -> int:
        """Edit this App's latest report comment on the PR, or post one. Only a comment made
        by this App counts: anyone can paste our marker into their own comment. `merge`
        builds the new body from the previous one (run history)."""
        latest, previous = None, None
        for page in range(1, 11):
            comments = self._request(
                installation_id, "GET", f"/repos/{owner}/{repo}/issues/{number}/comments",
                params={"per_page": 100, "page": page},
            ).json()  # fmt: skip
            for c in comments:  # oldest first
                app = c.get("performed_via_github_app") or {}
                if str(app.get("id")) == self.app_id and COMMENT_MARKER in (c.get("body") or ""):
                    latest, previous = int(c["id"]), c.get("body")
            if len(comments) < 100:
                break
        if merge:
            body = merge(previous)
        if COMMENT_MARKER not in body:
            body = f"{body}\n\n{COMMENT_MARKER}"
        if latest is None:
            return self.post_comment(installation_id, owner, repo, number, body)
        path = f"/repos/{owner}/{repo}/issues/comments/{latest}"
        self._request(installation_id, "PATCH", path, json={"body": body})
        return latest

    def create_review(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        number: int,
        commit_id: str,
        comments: list[dict],
    ) -> int:
        """One COMMENT review holding inline comments ({path, line, body}) on the head side."""
        resp = self._request(
            installation_id,
            "POST",
            f"/repos/{owner}/{repo}/pulls/{number}/reviews",
            json={
                "commit_id": commit_id,
                "event": "COMMENT",
                "comments": [{**c, "side": "RIGHT"} for c in comments],
            },
        )
        return int(resp.json()["id"])

    def list_open_prs(self, installation_id: int, owner: str, repo: str) -> list[dict]:
        return self._request(
            installation_id, "GET", f"/repos/{owner}/{repo}/pulls", params={"state": "open"}
        ).json()
