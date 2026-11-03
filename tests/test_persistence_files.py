"""`FILE_PERSISTENCE` - install-time writes to shell startup files, cron spools, systemd units.

**What this closes.** Re-scoring the recorded telemetry with rules alone
(`eval/score_rules.py`) showed ten attack cases the rules do not Block, and four of them share
one cause: `file_events` only reported the four planted *credential* paths, so
`gm04-rcfile-persist` and `rt06-persist-rcfile` appending to `~/.bashrc` left no trace at all.

**Why it is reached through the existing kprobe.** `chamber/policies/persistence-files.yaml`
uses the same `security_file_open` call and the same single `file` argument as the credential
policy that already works on the Chamber, so no new Tetragon JSON shape is involved -
`CLAUDE.md` requires a recorded fixture before coding against an unverified shape, and there is
no committed fixture carrying a different one.

**Why it is LOW and not HIGH.** It cannot fire until that policy is loaded on the Chamber, so
no recorded install contains a `file_event` for these paths and its false-positive rate is
unmeasured. `EXEC_SCHEDULED_PERSISTENCE` earned HIGH with 0 matches across 604 uncurated
packages; this one has no such evidence yet, and blocking on an unmeasured signal is the
mistake the weak-point gates exist to prevent. The promotion path is recorded on
`FILE_PERSISTENCE_SEVERITY` and in `docs/WEAKPOINTS.md` W5.
"""

import re
from pathlib import Path

import pytest
import yaml

from brain.rules import (
    BAIT_FILE_PREFIXES,
    FILE_PERSISTENCE_SEVERITY,
    PERSISTENCE_FILE_PREFIXES,
    Severity,
    evaluate,
)
from shared.contract import DetonateResult, ExecEvent, FileEvent
from tests.conftest import NPM_EXEC

POLICY_DIR = Path(__file__).parent.parent / "chamber" / "policies"


def lifecycle(pid: int = 50) -> ExecEvent:
    """npm's own `sh -c`, which is what makes a file open attributable to an install script."""
    return ExecEvent(ts="2026-01-01T00:00:01Z", pid=pid, ppid=1, binary="/usr/bin/sh",
                     args='-c "node setup.js"', parent_binary="/usr/local/bin/npm",
                     uid=10001, cwd="/work/node_modules/pkg")  # fmt: skip


def payload(pid: int = 51, ppid: int = 50, binary: str = "/usr/local/bin/node") -> ExecEvent:
    return ExecEvent(ts="2026-01-01T00:00:02Z", pid=pid, ppid=ppid, binary=binary,
                     args="setup.js", parent_binary="/usr/bin/sh", uid=10001,
                     cwd="/work/node_modules/pkg")  # fmt: skip


def result(*files: FileEvent, execs: list[ExecEvent] | None = None) -> DetonateResult:
    return DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                          exec_events=[NPM_EXEC, *(execs or [lifecycle(), payload()])],
                          connect_events=[], dns_queries=[], file_events=list(files),
                          stdout_tail="", stderr_tail="")  # fmt: skip


def opened(path: str, pid: int = 51, binary: str = "/usr/local/bin/node") -> FileEvent:
    return FileEvent(ts="2026-01-01T00:00:03Z", pid=pid, binary=binary, path=path)


def ids(res: DetonateResult) -> list[str]:
    return [h.rule_id for h in evaluate(res)]


# --- the cases this was written for ---


@pytest.mark.parametrize(
    "path",
    [
        "/home/runner/.bashrc",
        "/home/runner/.zshrc",
        "/home/runner/.profile",
        "/home/runner/.bash_profile",
        "/etc/profile.d/evil.sh",
        "/etc/cron.d/task",
        "/var/spool/cron/crontabs/runner",
        "/etc/systemd/system/evil.service",
    ],  # fmt: skip
)
def test_a_persistence_file_opened_by_an_install_script_is_flagged(path):
    hits = [h for h in evaluate(result(opened(path))) if h.rule_id == "FILE_PERSISTENCE"]
    assert len(hits) == 1
    assert hits[0].target == path


def test_gm04_appends_to_both_rc_files_and_each_is_reported_once():
    res = result(opened("/home/runner/.bashrc"), opened("/home/runner/.zshrc"))
    hits = [h for h in evaluate(res) if h.rule_id == "FILE_PERSISTENCE"]
    assert {h.target for h in hits} == {"/home/runner/.bashrc", "/home/runner/.zshrc"}


def test_the_same_path_twice_is_one_finding():
    res = result(opened("/home/runner/.bashrc"), opened("/home/runner/.bashrc"))
    assert ids(res).count("FILE_PERSISTENCE") == 1


# --- it must not be confused with credential theft ---


def test_a_bashrc_is_not_described_as_a_planted_credential():
    """The label a reviewer reads has to be true. Before this split, every file event was
    reported as "a planted fake credential", which a `.bashrc` is not."""
    hits = evaluate(result(opened("/home/runner/.bashrc")))
    assert [h.rule_id for h in hits] == ["FILE_PERSISTENCE"]
    assert "planted fake credential" not in hits[0].evidence
    assert "run code after the install ends" in hits[0].evidence


def test_a_credential_path_still_raises_the_credential_rule_at_high():
    hits = evaluate(result(opened("/home/runner/.aws/credentials")))
    assert [h.rule_id for h in hits] == ["CRED_FILE_ACCESS"]
    assert hits[0].severity == Severity.HIGH
    assert "planted fake credential" in hits[0].evidence


def test_both_classes_can_fire_in_one_run():
    res = result(opened("/home/runner/.aws/credentials"), opened("/home/runner/.bashrc"))
    assert set(ids(res)) == {"CRED_FILE_ACCESS", "FILE_PERSISTENCE"}


# --- attribution and exemptions ---


def test_an_open_outside_any_install_script_is_not_flagged():
    """The container's own entrypoint shell is not a lifecycle descendant. Without this gate,
    anything the image does at startup would be a finding."""
    outside = ExecEvent(ts="2026-01-01T00:00:00Z", pid=99, ppid=1,
                        binary="/usr/local/bin/docker-entrypoint.sh", args="npm install",
                        parent_binary=None, uid=0)  # fmt: skip
    res = result(opened("/home/runner/.bashrc", pid=99), execs=[outside])
    assert "FILE_PERSISTENCE" not in ids(res)


def test_the_npm_exemption_does_not_extend_to_persistence_paths():
    """npm reading ~/.npmrc is configuration and is exempt. npm writing ~/.bashrc is not
    configuration, so the same exemption must not cover it."""
    npm_proc = ExecEvent(ts="2026-01-01T00:00:02Z", pid=51, ppid=50,
                         binary="/usr/local/bin/npm", args="run build",
                         parent_binary="/usr/bin/sh", uid=10001)  # fmt: skip
    execs = [lifecycle(), npm_proc]
    assert "CRED_FILE_ACCESS" not in ids(result(opened("/home/runner/.npmrc"), execs=execs))
    assert "FILE_PERSISTENCE" in ids(result(opened("/home/runner/.bashrc"), execs=execs))


@pytest.mark.parametrize(
    "path",
    [
        "/work/node_modules/pkg/build/out.node",
        "/tmp/build.log",
        "/home/runner/.cache/thing",
        "/work/docs/bashrc-example.md",
        "/home/runner/.bashrc_disabled_by_nothing".replace("/.bashrc", "/.nothing"),
    ],  # fmt: skip
)
def test_unrelated_paths_raise_nothing(path):
    """Only paths the Chamber policies actually select are classified. An unclassified path
    must raise nothing rather than fall through to a generic label."""
    assert evaluate(result(opened(path))) == []


def test_prefix_semantics_match_tetragon_deliberately():
    """`/home/runner/.bashrc.bak` is flagged, and that is intentional rather than sloppy.

    The Tetragon policy selects with the `Prefix` operator, so the Chamber reports
    `.bashrc.bak` too. Making the rule exact-match would be *tighter* but would mean the
    Chamber traces a path the Brain silently drops - the same config/code drift that
    `test_every_path_the_persistence_policy_traces_is_classified_by_the_rules` exists to catch.
    Matching the kernel-side selector is the property worth keeping, and a script writing
    `~/.bashrc.bak` during an install is not innocent anyway: backing the file up is what you
    do before editing it."""
    hits = [h for h in evaluate(result(opened("/home/runner/.bashrc.bak")))
            if h.rule_id == "FILE_PERSISTENCE"]  # fmt: skip
    assert len(hits) == 1


# --- severity is deliberately LOW until measured ---


def test_it_is_high_and_that_severity_was_measured_not_assumed():
    """Promoted on Nov 3 after the policy was deployed and the 104 benign controls were
    re-detonated live: 0 of 104 opened any of these paths, `truncated` stayed False on all 106
    runs, and every record carried `file_events` so the zero is a real absence rather than dead
    tracing. It shipped at LOW until that existed."""
    assert FILE_PERSISTENCE_SEVERITY == Severity.HIGH
    hits = evaluate(result(opened("/home/runner/.bashrc")))
    assert hits[0].severity == Severity.HIGH


def test_high_means_the_persistence_cases_now_block():
    from brain.llm import LlmOutcome
    from brain.verdict import combine

    res = result(opened("/home/runner/.bashrc"))
    final = combine(evaluate(res), LlmOutcome("m", error="x", skipped=True), res)
    assert final.title == "Blocked"
    assert final.conclusion == "failure", "gm04 and rt06 previously fired no rule at all"


# --- the Chamber policy and these rules must not drift apart ---


def _policy_prefixes(name: str) -> list[str]:
    doc = yaml.safe_load((POLICY_DIR / name).read_text(encoding="utf-8"))
    out: list[str] = []
    for kprobe in doc["spec"]["kprobes"]:
        for selector in kprobe.get("selectors", []):
            for arg in selector.get("matchArgs", []):
                assert arg["operator"] == "Prefix", (
                    f"{name} uses {arg['operator']!r}; the rules classify by str.startswith, "
                    "so a different operator would mean they no longer agree"
                )
                out += arg["values"]
    return out


def test_every_path_the_persistence_policy_traces_is_classified_by_the_rules():
    """The failure this prevents: a path added to the Tetragon policy, reported by the Chamber,
    and then silently dropped (or mislabelled) by the Brain because nobody updated the rules."""
    assert sorted(_policy_prefixes("persistence-files.yaml")) == sorted(PERSISTENCE_FILE_PREFIXES)


def test_every_path_the_credential_policy_traces_is_classified_by_the_rules():
    assert sorted(_policy_prefixes("credential-files.yaml")) == sorted(BAIT_FILE_PREFIXES)


def test_the_two_policies_do_not_overlap():
    """A path in both would get whichever rule the classifier checks first, which is a coin
    flip nobody chose. `~/.ssh/` is credential-class; it must not reappear as persistence."""
    bait, persist = set(BAIT_FILE_PREFIXES), set(PERSISTENCE_FILE_PREFIXES)
    assert not (bait & persist)
    for b in bait:
        for p in persist:
            assert not (b.startswith(p) or p.startswith(b)), f"{b!r} and {p!r} overlap"


def test_the_new_policy_reuses_the_already_verified_event_shape():
    """It must stay on `security_file_open` with one `file` arg at index 0 - the shape
    `chamber/telemetry.py` parses and the comment there says was verified on the Chamber. A new
    kprobe would need a recorded fixture first (CLAUDE.md)."""
    doc = yaml.safe_load((POLICY_DIR / "persistence-files.yaml").read_text(encoding="utf-8"))
    existing = yaml.safe_load((POLICY_DIR / "credential-files.yaml").read_text(encoding="utf-8"))
    new_probes, old_probes = doc["spec"]["kprobes"], existing["spec"]["kprobes"]
    assert len(new_probes) == 1
    assert new_probes[0]["call"] == old_probes[0]["call"] == "security_file_open"
    assert new_probes[0]["args"] == old_probes[0]["args"]
    assert doc["metadata"]["name"] != existing["metadata"]["name"], (
        "a separate policy name is what makes this an additive deploy"
    )


def test_provisioning_installs_every_policy_in_the_directory():
    """A mutation that deleted the `install` line from setup.sh passed the whole suite: the
    repo would describe tracing the Chamber did not do, and nothing would say so. The glob is
    what makes a new policy file arrive on the box without another edit here."""
    setup = (POLICY_DIR.parent / "provision" / "setup.sh").read_text(encoding="utf-8")
    install_lines = [
        ln for ln in setup.splitlines()
        if "tetragon.tp.d" in ln and ln.strip().startswith("install")
    ]  # fmt: skip
    assert install_lines, "setup.sh no longer installs any Tetragon policy"
    globbed = [ln for ln in install_lines if "chamber/policies/*.yaml" in ln]
    named = " ".join(install_lines)
    for policy in sorted(POLICY_DIR.glob("*.yaml")):
        assert globbed or policy.name in named, (
            f"{policy.name} would never reach /etc/tetragon/tetragon.tp.d on a fresh provision"
        )
    assert "systemctl restart tetragon" in setup, "a new policy only loads on restart"


def test_the_policy_stays_selective_rather_than_tracing_a_broad_prefix():
    """A prefix like `/work/` or `/home/runner/` would report every file npm writes, flood the
    event cap, and - because truncation fails closed - turn every verdict into Could not
    verify. That is the volume problem W5 describes."""
    for prefix in _policy_prefixes("persistence-files.yaml"):
        assert prefix not in ("/", "/work/", "/home/runner/", "/etc/", "/tmp/")
        assert len(prefix) > 10, f"{prefix!r} is broad enough to be a volume risk"
        assert not re.fullmatch(r"/home/runner/\.?", prefix)
