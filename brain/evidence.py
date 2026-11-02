"""Evidence grounding: the model's factual claims are checked against the kernel record.

Structured output guarantees the *shape* of the model's answer, not its truth. So every
event the model sees carries an ID, the model must cite IDs for its evidence, and code (not
the model) decides what each claim is worth:

- an ID that isn't in this job's index is rejected (invented, or copied from PR text: IDs
  are an HMAC of the job ID, so an author can't predict them);
- an "observed" claim needs at least one cited event of its own type (an exec claim cited to
  a DNS record is not support);
- a "source_inferred" claim (dangerous code seen in the diff or a captured script that never
  ran) is kept but labelled as such: it is never presented as something the kernel saw.

The report shows each supported claim as the *kernel's* rendering of the cited event plus
the model's one-line reason, so a hallucinated detail can't reach the comment through this
path. Hosts and IPs named in the model's prose that appear neither in the telemetry nor in
the diff are listed as unsupported mentions. None of this changes a verdict.
"""

import hashlib
import hmac
import re
from dataclasses import dataclass, field

from shared.contract import DetonateResult

# event_type the model may claim -> the index sources that can support it
SUPPORTS = {
    "exec": ("exec",),
    "connect": ("connect",),
    "dns": ("dns",),
    "file": ("file",),
}
PREFIX = {"exec": "x", "connect": "c", "dns": "d", "file": "f"}
_ID_HEX = 6
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
# Dotted names in prose that are file names, not hosts.
_FILE_SUFFIXES = frozenset(
    "js mjs cjs ts json sh bash md py lock yml yaml txt node gz tgz zip exe bin log toml "
    "cfg ini html css map".split()
)
MAX_MENTIONS = 10


@dataclass(frozen=True)
class Item:
    id: str
    source: str  # exec | connect | dns | file
    text: str  # the kernel's own rendering of the event (for the report)


def _event_id(job_id: str, source: str, i: int, taken: set[str]) -> str:
    digest = hmac.new(job_id.encode(), f"{source}:{i}".encode(), hashlib.sha256).hexdigest()
    eid = PREFIX[source] + digest[:_ID_HEX]
    return eid if eid not in taken else f"{eid}{i}"


def build_index(result: DetonateResult) -> dict[str, Item]:
    """Every event in the (redacted) result, keyed by a job-scoped ID. Insertion order is
    telemetry order, which compact_telemetry relies on to label each entry."""
    index: dict[str, Item] = {}

    def add(source: str, i: int, text: str) -> None:
        eid = _event_id(result.job_id, source, i, set(index))
        index[eid] = Item(eid, source, text)

    for i, e in enumerate(result.exec_events):
        add("exec", i, f"exec {e.binary} {e.args}".strip())
    for i, c in enumerate(result.connect_events):
        name = c.resolved_domain or "no DNS lookup"
        blocked = " (blocked)" if c.protocol != "tcp" else ""
        add("connect", i, f"{c.binary} → {c.protocol}:{c.daddr}:{c.dport} ({name}){blocked}")
    for i, q in enumerate(result.dns_queries):
        add("dns", i, f"DNS {q.domain} → {', '.join(q.answers) or 'no answer'}")
    for i, f in enumerate(result.file_events):
        add("file", i, f"{f.binary} opened {f.path}")
    return index


def ids_by_source(index: dict[str, Item]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {s: [] for s in PREFIX}
    for item in index.values():
        out[item.source].append(item.id)
    return out


@dataclass(frozen=True)
class CheckedClaim:
    event_type: str
    kind: str  # observed | source_inferred
    why: str
    items: tuple[Item, ...]  # the cited events that support it (empty for source_inferred)


@dataclass(frozen=True)
class Rejected:
    event_type: str
    reason: str


@dataclass(frozen=True)
class Grounding:
    supported: list[CheckedClaim] = field(default_factory=list)
    rejected: list[Rejected] = field(default_factory=list)
    unsupported_mentions: list[str] = field(default_factory=list)  # hosts/IPs not on record

    @property
    def claims(self) -> int:
        return len(self.supported) + len(self.rejected)

    def summary(self) -> dict:
        return {
            "claims": self.claims,
            "supported": len(self.supported),
            "rejected": len(self.rejected),
            "source_inferred": sum(c.kind == "source_inferred" for c in self.supported),
            "unsupported_mentions": len(self.unsupported_mentions),
        }


def check(verdict, index: dict[str, Item], corpus: str) -> Grounding:
    """`verdict` is an LlmVerdict. `corpus` is everything the claims may legitimately quote:
    the telemetry text plus the diff and captured scripts."""
    supported: list[CheckedClaim] = []
    rejected: list[Rejected] = []
    for ev in verdict.key_evidence:
        unknown = [r for r in ev.refs if r not in index]
        if unknown:
            rejected.append(Rejected(ev.event_type, f"cites unknown event id {unknown[0][:20]!r}"))
            continue
        cited = tuple(index[r] for r in ev.refs)
        if ev.kind == "source_inferred":
            supported.append(CheckedClaim(ev.event_type, ev.kind, ev.why_it_matters, ()))
            continue
        matching = tuple(i for i in cited if i.source in SUPPORTS.get(ev.event_type, ()))
        if not matching:
            reason = "cites no runtime event" if not cited else "cited events are the wrong type"
            rejected.append(Rejected(ev.event_type, reason))
            continue
        supported.append(CheckedClaim(ev.event_type, ev.kind, ev.why_it_matters, matching))
    prose = " ".join((verdict.observed_behavior, verdict.explanation))
    return Grounding(supported, rejected, unsupported_mentions(prose, corpus))


def unsupported_mentions(prose: str, corpus: str) -> list[str]:
    """IPv4 addresses and hostnames in the model's prose that the record doesn't contain."""
    haystack = corpus.lower()
    found: list[str] = []
    candidates = _IPV4_RE.findall(prose) + [
        h for h in _HOST_RE.findall(prose) if h.rsplit(".", 1)[-1].lower() not in _FILE_SUFFIXES
    ]
    for token in candidates:
        t = token.lower().rstrip(".")
        if t not in haystack and t not in found:
            found.append(t)
    return found[:MAX_MENTIONS]


def corpus_for(result: DetonateResult, diff: str, extra: str = "") -> str:
    parts = [diff, extra]
    for e in result.exec_events:
        parts += [e.binary, e.args, e.cwd or ""]
    for c in result.connect_events:
        parts += [c.daddr, c.resolved_domain or ""]
    for q in result.dns_queries:
        parts += [q.domain, *q.answers]
    for f in result.file_events:
        parts.append(f.path)
    for s in result.executed_scripts:
        parts += [s.path, s.content]
    return "\n".join(parts)
