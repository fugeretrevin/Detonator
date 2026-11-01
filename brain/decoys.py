"""Canary credentials and decoy tools, Brain side (HARDENING_PLAN P1.2).

The Chamber plants per-run fake tokens (env, ~/.npmrc, ~/.aws) and decoy CLIs on PATH, and
returns the values in the signed result. A decoy value showing up in what the sandbox did
(a process's arguments, a DNS name, its output) means something harvested credentials and
used or sent them. Values are redacted before anything reaches the model or GitHub: they
are fake, but token-shaped strings in public PR comments trip secret scanning.
"""

from brain.rules import RuleHit, Severity
from shared.contract import DetonateResult

DECOY_BIN = "/usr/local/decoy/bin/"  # chamber/decoys.py
MIN_DECOY_LEN = 12


def _values(result: DetonateResult) -> dict[str, str]:
    return {k: v for k, v in result.decoys.items() if len(v) >= MIN_DECOY_LEN}


def decoy_hits(result: DetonateResult) -> list[RuleHit]:
    hits: list[RuleHit] = []
    seen: set[tuple[str, str]] = set()

    def hit(name: str, where: str, ts: str, pid: int) -> None:
        if (name, where) in seen:
            return
        seen.add((name, where))
        hits.append(RuleHit("DECOY_CREDENTIAL_SEEN", Severity.CRITICAL,
                            f"planted decoy {name} appeared in {where}: the install harvested "
                            "credentials and used or sent them", ts, pid, target=name))  # fmt: skip

    for name, value in _values(result).items():
        low = value.lower()
        for e in result.exec_events:
            if value in e.args:
                hit(name, f"the arguments of {e.binary.rsplit('/', 1)[-1]} (pid {e.pid})", e.ts,
                    e.pid)  # fmt: skip
        for q in result.dns_queries:
            if low in q.domain.lower():
                hit(name, "a DNS lookup", q.ts, 0)
        if value in result.stdout_tail or value in result.stderr_tail:
            hit(name, "the install's output", "", 0)

    for e in result.exec_events:
        if e.binary.startswith(DECOY_BIN):
            tool = e.binary[len(DECOY_BIN) :]
            hits.append(RuleHit("DECOY_TOOL_INVOKED", Severity.HIGH,
                                f"install ran the decoy `{tool}` CLI (pid {e.pid}): {e.args[:120]}",
                                e.ts, e.pid, target=tool))  # fmt: skip
    return hits


def redact_text(text: str, result: DetonateResult) -> str:
    for name, value in _values(result).items():
        text = text.replace(value, f"<decoy:{name}>")
        text = text.replace(value.lower(), f"<decoy:{name}>")
    return text


def redact(result: DetonateResult) -> DetonateResult:
    """A copy safe to show the model or post: every decoy value replaced by its name."""
    if not _values(result):
        return result
    r = lambda s: redact_text(s, result)  # noqa: E731
    return result.model_copy(update={
        "exec_events": [e.model_copy(update={"args": r(e.args)}) for e in result.exec_events],
        "dns_queries": [q.model_copy(update={"domain": r(q.domain)}) for q in result.dns_queries],
        "stdout_tail": r(result.stdout_tail),
        "stderr_tail": r(result.stderr_tail),
        "executed_scripts": [s.model_copy(update={"content": r(s.content)})
                             for s in result.executed_scripts],
        "decoys": {k: "<redacted>" for k in result.decoys},
    })  # fmt: skip
