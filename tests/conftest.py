"""Shared test fixtures.

`NPM_EXEC` is the baseline process event every real detonation produces: running
`npm install` always execs npm itself. Synthetic results need it because a completed run with
*no* exec events means the collector was blind, which `brain.verdict` now refuses to call
"Clean" (see `unverified_reason`). It is deliberately boring so it fires no exec rule.
"""

from shared.contract import ExecEvent

NPM_EXEC = ExecEvent(
    ts="2026-11-02T00:00:00Z",
    pid=100,
    ppid=1,
    binary="/usr/bin/npm",
    parent_binary="/bin/sh",
    args="install --no-audit --no-fund",
    cwd="/job/src",
    uid=0,
)
