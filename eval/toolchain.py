"""Report-only accounting for benign "Could not verify" outcomes (W3).

This module is **not** part of the detection pipeline. It reads a finished detonation
and labels *why* a benign install did not reach a clean verdict. It cannot change a
verdict, a rule hit, or a stamped result — it only names a cause that the raw
telemetry already records.

It exists so that W3 ("6 of 104 benign packages cannot be verified") can be stated as
a precise, mechanical split rather than an open coverage gap:

  * ``unsupported-toolchain`` — the install ran ``node-gyp`` / a native compile and
    failed because the sandbox ships no C toolchain. This is **by design**: a compiler
    in the sandbox hands every payload a compiler and removes the network signal that
    ``EXEC_DROPPED_BINARY`` depends on. See ``eval/TOOLCHAIN_TRADEOFF.md``. These are
    the reproducible, deliberate cases — a smaller blast radius, not a failure to
    verify.
  * ``cdn-timeout`` — the install exceeded the install timeout. Measured to be a
    registry/CDN speed artifact, not a sandbox property: ``eval/PERSISTENCE.md`` shows
    ``biome`` (5.8 s) and ``cypress`` (40 s) completing well inside the 240 s limit on
    a Nov 3 re-run after timing out on Nov 2.
  * ``genuine-failure`` — a non-zero install with no toolchain signature. Nothing in
    the stamped corpus lands here; the label exists so one would be visible if it ever
    did.
  * ``verified`` — the install exited 0; not an unverified case at all.

The input is a detonation telemetry dict (the shape ``eval/*_telemetry/*.json`` use),
or any mapping carrying ``status``, ``exit_code`` and — when available —
``stderr_tail`` and ``exec_events``. No network, no model, no Chamber access.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

UNSUPPORTED_TOOLCHAIN = "unsupported-toolchain"
CDN_TIMEOUT = "cdn-timeout"
GENUINE_FAILURE = "genuine-failure"
VERIFIED = "verified"

# A native-module install that needs a C/C++ toolchain leaves one of these in stderr or
# in the exec chain. node-gyp drives the build; the failure the slim image produces is a
# missing compiler (`cc`/`g++`/`make` not found) once node-gyp reaches the build step.
# Matched case-insensitively. These are signatures of the *build path*, not of any single
# package, so the classifier does not depend on a hardcoded package list.
_TOOLCHAIN_PATTERNS = (
    r"node-gyp\b",
    r"node-pre-gyp\b",
    r"prebuild-install\b",
    r"gyp ERR!",
    r"gyp: .*not found",
    r"\b(?:cc|cc1|cc1plus|gcc|g\+\+|c\+\+|clang|clang\+\+)\s*:\s*(?:command\s+)?not found",
    r"\bmake\s*:\s*(?:command\s+)?not found",
    r"\bmake:\s*\*\*\*",  # a failing make build step
    r"no acceptable C(?:\+\+)? compiler found",
    r"which:\s*no\s+(?:cc|gcc|g\+\+|make)\b",
)
_TOOLCHAIN_RE = re.compile("|".join(_TOOLCHAIN_PATTERNS), re.IGNORECASE)


def telemetry_shows_native_build(telemetry: Mapping[str, Any]) -> bool:
    """True when the recorded install attempted a native (node-gyp / compiler) build.

    Looks at ``stderr_tail`` first, then the recorded ``exec_events`` — a build can be
    visible in the process chain (``sh -c "node-gyp rebuild"``) even when stderr was
    clipped.
    """
    stderr = telemetry.get("stderr_tail") or ""
    if _TOOLCHAIN_RE.search(stderr):
        return True
    for event in telemetry.get("exec_events") or []:
        blob = f"{event.get('binary', '')} {event.get('args', '')}"
        if _TOOLCHAIN_RE.search(blob):
            return True
    return False


def classify(telemetry: Mapping[str, Any]) -> str:
    """Label why a benign detonation did not verify. Report-only; never a verdict.

    Order matters: a native build is named whatever the exit route (a compile that is
    also slow is still an unsupported toolchain, not a CDN artifact), then timeouts,
    then anything genuinely broken.
    """
    status = telemetry.get("status")
    exit_code = telemetry.get("exit_code")

    if status == "completed" and exit_code == 0:
        return VERIFIED
    if telemetry_shows_native_build(telemetry):
        return UNSUPPORTED_TOOLCHAIN
    if status == "timeout":
        return CDN_TIMEOUT
    return GENUINE_FAILURE


def account(telemetries: Iterable[Mapping[str, Any]]) -> Counter[str]:
    """Count the classifications across a set of detonations.

    Lets the eval state the W3 split ("N unsupported-toolchain, M CDN-timeout, ...")
    from data rather than from a remembered number.
    """
    return Counter(classify(t) for t in telemetries)
