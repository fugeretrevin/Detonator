from datetime import UTC, datetime, timedelta

import httpx

from brain.github_client import ChangedFile, added_registry_dependencies
from brain.newpkg import MISSING, new_package_hits, registry_resolver
from brain.rules import Severity

NOW = datetime(2026, 11, 2, tzinfo=UTC)


def iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


def test_nonexistent_package_flagged():
    hits = new_package_hits(["totally-not-real-xyz"], lambda n: MISSING, now=NOW)
    assert [(h.rule_id, h.severity, h.target) for h in hits] == [
        ("DEP_NEW_PACKAGE", Severity.LOW, "totally-not-real-xyz")
    ]
    assert "does not exist" in hits[0].evidence


def test_young_package_flagged_old_package_not():
    resolver = {"fresh": iso(2), "old": iso(900)}.get
    hits = new_package_hits(["fresh", "old"], resolver, now=NOW)
    assert [h.target for h in hits] == ["fresh"] and "2.0 days ago" in hits[0].evidence


def test_lookup_failure_is_silent():
    assert new_package_hits(["x"], lambda n: None, now=NOW) == []


def test_no_resolver_means_no_hits():
    assert new_package_hits(["x"], None, now=NOW) == []


def test_registry_deps_exclude_git_https_file_specs():
    patch = (
        '@@ -1,1 +1,6 @@\n   "dependencies": {\n'
        '+    "good-pkg": "^1.2.3",\n'
        '+    "aliased": "npm:real-target@^1.0.0",\n'
        '+    "from-git": "git+https://github.com/x/y.git",\n'
        '+    "from-url": "https://example.com/a.tgz",\n'
        '+    "from-file": "file:../local"\n   }'
    )
    names = added_registry_dependencies([ChangedFile(filename="package.json", status="modified",
                                                     patch=patch)])  # fmt: skip
    assert names == ["good-pkg", "real-target"]  # alias reported under its target


def test_real_resolver_against_registry_shapes():
    # 404 -> MISSING; a 'time.created' -> that string; error -> None. No network (MockTransport).
    def handler(request: httpx.Request) -> httpx.Response:
        if "missingpkg" in request.url.path:
            return httpx.Response(404)
        if "boom" in request.url.path:
            return httpx.Response(500)
        return httpx.Response(200, json={"time": {"created": "2020-01-01T00:00:00.000Z"}})

    r = registry_resolver(httpx.Client(transport=httpx.MockTransport(handler)))
    assert r("missingpkg") == MISSING
    assert r("boom") is None
    assert r("lodash") == "2020-01-01T00:00:00.000Z"
