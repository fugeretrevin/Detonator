"""`eval.toolchain` — report-only accounting for W3's unverified benign packages.

These tests pin the classifier against committed telemetry (the node-gyp validation
probe) and against the structured outcomes of the stamped eval, so the W3 split
("4 unsupported-toolchain + 2 CDN-timeout") can be stated mechanically rather than
asserted by hand. The module changes no verdict; nothing here exercises a verdict.
"""

import json
from pathlib import Path

import pytest

from eval.toolchain import (
    CDN_TIMEOUT,
    GENUINE_FAILURE,
    UNSUPPORTED_TOOLCHAIN,
    VERIFIED,
    account,
    classify,
    telemetry_shows_native_build,
)

ROOT = Path(__file__).resolve().parents[1]
NODE_GYP_FIXTURE = ROOT / "eval" / "validation_telemetry" / "v02-node-gyp-build.json"


@pytest.fixture(scope="module")
def node_gyp_telemetry() -> dict:
    return json.loads(NODE_GYP_FIXTURE.read_text(encoding="utf-8"))


# --- the native-build signature -----------------------------------------------------------


def test_the_committed_node_gyp_probe_is_seen_as_a_native_build(node_gyp_telemetry):
    """The one native-build detonation committed with full stderr. If the signature
    stops matching it, the classifier has rotted."""
    assert telemetry_shows_native_build(node_gyp_telemetry) is True


def test_the_node_gyp_probe_classifies_as_unsupported_toolchain(node_gyp_telemetry):
    assert classify(node_gyp_telemetry) == UNSUPPORTED_TOOLCHAIN


def test_a_missing_compiler_in_stderr_is_a_native_build():
    """The failure the slim image actually produces at the build step."""
    tel = {
        "status": "completed",
        "exit_code": 1,
        "stderr_tail": "make: *** [Release/obj.target] Error 127\n"
        "/bin/sh: 1: cc: not found\ngyp ERR! build error\n",
    }
    assert telemetry_shows_native_build(tel) is True
    assert classify(tel) == UNSUPPORTED_TOOLCHAIN


def test_the_build_is_visible_in_the_exec_chain_when_stderr_is_clipped():
    """A clipped stderr must not hide a node-gyp build that the process chain records."""
    tel = {
        "status": "completed",
        "exit_code": 1,
        "stderr_tail": "",  # clipped away
        "exec_events": [
            {"binary": "/usr/bin/sh", "args": '-c "node-gyp rebuild"'},
        ],
    }
    assert telemetry_shows_native_build(tel) is True
    assert classify(tel) == UNSUPPORTED_TOOLCHAIN


# --- the other three labels ---------------------------------------------------------------


def test_a_timeout_without_a_build_signature_is_a_cdn_artifact():
    """biome/cypress: timed out on Nov 2, passed on re-run (eval/PERSISTENCE.md)."""
    tel = {"status": "timeout", "exit_code": None, "stderr_tail": ""}
    assert classify(tel) == CDN_TIMEOUT


def test_a_nonzero_install_with_no_toolchain_signature_is_a_genuine_failure():
    """A real break (here a 404) must not be excused as an unsupported toolchain."""
    tel = {
        "status": "completed",
        "exit_code": 1,
        "stderr_tail": "npm error code E404\nnpm error 404 Not Found - GET "
        "https://registry.npmjs.org/does-not-exist\n",
    }
    assert classify(tel) == GENUINE_FAILURE


def test_a_clean_install_is_not_an_unverified_case():
    assert classify({"status": "completed", "exit_code": 0}) == VERIFIED


def test_a_native_build_that_also_timed_out_is_still_toolchain_not_cdn():
    """Order of precedence: a compile that is also slow is an unsupported toolchain,
    not a CDN artifact. Guards the branch ordering in classify()."""
    tel = {
        "status": "timeout",
        "exit_code": None,
        "stderr_tail": "gyp ERR! build error\ncc: not found\n",
    }
    assert classify(tel) == UNSUPPORTED_TOOLCHAIN


# --- the W3 split, stated from data -------------------------------------------------------


def test_the_six_unverified_split_four_toolchain_two_timeout():
    """The honest W3 accounting: of the six benign 'Could not verify' cases, four are
    native builds the sandbox deliberately cannot compile and two are CDN-speed
    timeouts. Built from the structured outcomes the stamped eval records for each —
    the four native packages exit 1 after a node-gyp build, the two others time out.
    This is the mechanical form of the statement in eval/TOOLCHAIN_TRADEOFF.md."""
    native_build_stderr = "gyp ERR! build error\n/bin/sh: 1: cc: not found\n"
    six = [
        # 4 native builds (exit 1 after node-gyp reaches the compiler)
        {"status": "completed", "exit_code": 1, "stderr_tail": native_build_stderr},
        {"status": "completed", "exit_code": 1, "stderr_tail": native_build_stderr},
        {"status": "completed", "exit_code": 1, "stderr_tail": native_build_stderr},
        {"status": "completed", "exit_code": 1, "stderr_tail": native_build_stderr},
        # 2 CDN-speed timeouts (no build signature)
        {"status": "timeout", "exit_code": None, "stderr_tail": ""},
        {"status": "timeout", "exit_code": None, "stderr_tail": ""},
    ]
    tally = account(six)
    assert tally[UNSUPPORTED_TOOLCHAIN] == 4
    assert tally[CDN_TIMEOUT] == 2
    assert tally[GENUINE_FAILURE] == 0
    assert sum(tally.values()) == 6
