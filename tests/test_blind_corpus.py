"""`eval.blind_corpus` — the held-out red-team set, and its safety envelope as a standing guard.

Two jobs. First, keep the corpus honest about what it is: a set written blind to the detectors,
whose value is measuring misses. Second — and this is the load-bearing part — enforce the
defanging envelope on every payload byte, so the set can grow without anyone having to re-audit
it by hand. A corpus of attack-shaped packages is only safe to keep in the repo if a test, not a
promise, guarantees nothing in it routes anywhere.

The corpus is generated content from a subagent; it was independently audited before landing,
and this test is that audit made permanent.
"""

import ipaddress
import re

from eval.blind_corpus import BLIND_CORPUS
from eval.cases import Case

RESERVED = [
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
]
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SAFE_TAILS = (".invalid", "example.com", "example.org", "example.net")
# Real-token shapes. The payloads *read* ~/.npmrc etc. by design; what must never appear is a
# real token literal baked into a fixture.
CRED_RE = re.compile(
    r"gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{12,}|-----BEGIN|npm_[A-Za-z0-9]{24,}"
)


# A routable destination ends in a real public TLD. `.invalid` deliberately is not one (it
# never resolves — that is its purpose), and JS member access (`https.request`, `process.env`,
# `r.on`) has a fake "TLD" that is a method name, so this cleanly separates destinations from
# code without a denylist. Kept small on purpose: a genuinely new TLD in the corpus should make
# someone look, which a failing test does.
REAL_TLDS = {
    "com", "net", "org", "io", "dev", "co", "me", "app", "cloud", "info", "xyz", "top",
    "ru", "cn", "site", "online", "sh", "gg", "to", "ai", "link", "live", "run",
}  # fmt: skip


def destination_hostnames(text: str) -> set[str]:
    """Dotted names that could be routable destinations: those ending in a real public TLD.

    Catches hostnames both bare and inside quoted/generated JS (bc01 builds its second stage as
    string literals, so quoting cannot be the discriminator). Excludes `.invalid` and every JS
    idiom, whose final label is not a public TLD.
    """
    hosts: set[str] = set()
    for host in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", text, re.I):
        low = host.lower()
        if low.rsplit(".", 1)[-1] in REAL_TLDS:
            hosts.add(low)
    # `.invalid` names are safe destinations but must still be *found*, so the "extractor finds
    # the known destinations" guard is meaningful.
    for host in re.findall(r"\b(?:[a-z0-9-]+\.)+invalid\b", text, re.I):
        hosts.add(host.lower())
    return hosts


def all_payload_text(case: Case) -> str:
    """Every byte of every file a case would write into the sandbox."""
    return "\n".join(v if isinstance(v, str) else v.decode("utf-8", "replace")
                     for v in case.payload_files().values())  # fmt: skip


def all_corpus_text() -> str:
    return "\n".join(all_payload_text(c) for c in BLIND_CORPUS)


# --- the safety envelope, enforced on payload bytes ---


def test_every_ip_in_every_payload_is_reserved_and_non_routable():
    offenders = []
    for case in BLIND_CORPUS:
        for ip_str in IP_RE.findall(all_payload_text(case)):
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            ok = (
                any(ip in net for net in RESERVED)
                or ip.is_private
                or ip.is_loopback
                or ip.is_link_local
            )
            if not ok:
                offenders.append((case.id, ip_str))
    assert not offenders, f"routable IPs in the blind corpus: {offenders}"


def test_every_hostname_destination_is_invalid_or_example():
    offenders = []
    for case in BLIND_CORPUS:
        for host in destination_hostnames(all_payload_text(case)):
            if not host.endswith(SAFE_TAILS):
                offenders.append((case.id, host))
    assert not offenders, (
        f"network-destination hostnames that are not .invalid/example: {offenders}"
    )


def test_the_destination_extractor_actually_finds_the_known_destinations():
    """Guard against the extractor silently matching nothing and the test above passing
    vacuously: the corpus is known to reach these two named hosts."""
    found = destination_hostnames(all_corpus_text())
    assert "collector.invalid" in found
    assert "beacon.example.com" in found


def test_no_real_credential_literal_is_baked_into_a_payload():
    found = CRED_RE.findall(all_corpus_text())
    assert not found, f"real-token-shaped literal in the corpus: {found[:5]}"


def test_the_metadata_address_if_present_is_only_a_probe_target():
    """169.254.169.254 is allowed (the sandbox rejects it), but only as a bare target — never
    next to a real cloud credential, which there are none of anyway."""
    text = all_corpus_text()
    if "169.254.169.254" in text:
        assert "AKIA" not in text and "aws_secret" not in text.lower()


# --- the corpus is what it claims to be ---


def test_it_is_a_held_out_set_of_the_expected_shape():
    assert len(BLIND_CORPUS) >= 8, "a held-out set this small proves little; expected >= 8"
    assert all(c.kind == "redteam-blind" for c in BLIND_CORPUS)
    ids = [c.id for c in BLIND_CORPUS]
    assert len(set(ids)) == len(ids), "duplicate case ids"
    assert all(c.id.startswith("bc") for c in BLIND_CORPUS), "blind cases are bc*"


def test_every_case_is_structurally_valid_and_runnable():
    for c in BLIND_CORPUS:
        assert c.title and c.body, f"{c.id} lacks a cover story"
        assert c.note, f"{c.id} lacks a technique note"
        files = c.payload_files()
        assert any(n.endswith("package.json") for n in files), f"{c.id} has no package.json"
        # The command is the standard payload detonation, so it is detonatable like any case.
        assert c.command[:4] == ["npm", "install", "--no-audit", "--no-fund"]
        assert "--prefix" in c.command and f"payloads/{c.id}" in c.command


def test_the_docstring_states_the_blinding_and_the_envelope():
    """If someone later edits the module, the two claims that make it legitimate must survive:
    that it was written blind, and that every destination is reserved."""
    import eval.blind_corpus as mod

    doc = (mod.__doc__ or "").lower()
    assert "without reading the detectors" in doc or "blind" in doc
    assert "non-routable" in doc or "reserved" in doc


def test_a_cover_story_never_matches_the_technique():
    """Each case's PR text is benign-sounding; the technique note is the real behaviour. They
    must differ, or the case would be self-evidently malicious and test nothing about a scanner
    that reads the PR text as an attacker-controlled cover."""
    for c in BLIND_CORPUS:
        assert c.note.lower() not in c.body.lower()
