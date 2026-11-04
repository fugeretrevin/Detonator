"""`eval.validation_set` — the W12 blind validation set, and its safety envelope as a guard.

Like `test_blind_corpus`, this enforces the defanging on every payload byte so the attack-shaped
fixtures cannot route anywhere, and checks the set is the mixed, pre-labelled shape W12 needs:
benign and malicious cases, each with a frozen expected verdict committed before any tool run.
"""

import ipaddress
import json
import re
from pathlib import Path

from eval.cases import Case
from eval.validation_set import VALIDATION_SET

ROOT = Path(__file__).resolve().parents[1]
LABELS = ROOT / "eval" / "validation_labels.json"
RESERVED = [ipaddress.ip_network(n) for n in ("203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24")]
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SAFE_TAILS = (".invalid", "example.com", "example.org", "example.net")
REAL_TLDS = {"com", "net", "org", "io", "dev", "co", "me", "app", "cloud", "info", "xyz",
             "top", "ru", "cn", "site", "online", "sh", "gg", "to", "ai"}  # fmt: skip
CRED_RE = re.compile(
    r"gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{12,}|-----BEGIN|npm_[A-Za-z0-9]{24,}"
)


def payload_text(case: Case) -> str:
    return "\n".join(v.decode("utf-8", "replace") if isinstance(v, bytes) else v
                     for v in case.payload_files().values())  # fmt: skip


def all_text() -> str:
    return "\n".join(payload_text(c) for c in VALIDATION_SET)


def destination_hosts(text: str) -> set[str]:
    hosts = set()
    for host in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", text, re.I):
        low = host.lower()
        if low.rsplit(".", 1)[-1] in REAL_TLDS or low.endswith(".invalid"):
            hosts.add(low)
    return hosts


def test_every_ip_is_reserved_non_routable():
    offenders = []
    for case in VALIDATION_SET:
        for s in IP_RE.findall(payload_text(case)):
            try:
                ip = ipaddress.ip_address(s)
            except ValueError:
                continue
            if not (any(ip in n for n in RESERVED) or ip.is_private or ip.is_loopback):
                offenders.append((case.id, s))
    assert not offenders, f"routable IPs: {offenders}"


def test_every_destination_host_is_invalid_or_example():
    offenders = [
        (c.id, h) for c in VALIDATION_SET for h in destination_hosts(payload_text(c))
        if not h.endswith(SAFE_TAILS)
    ]  # fmt: skip
    assert not offenders, f"non-defanged destinations: {offenders}"


def test_no_real_credential_literal():
    assert not CRED_RE.findall(all_text())


def test_it_is_a_mixed_pre_labelled_set():
    assert 12 <= len(VALIDATION_SET) <= 16
    assert all(c.kind == "validation" for c in VALIDATION_SET)
    labels = json.loads(LABELS.read_text(encoding="utf-8"))["cases"]
    ids = {c.id for c in VALIDATION_SET}
    assert ids == set(labels), f"labels and cases disagree: {ids ^ set(labels)}"
    verdicts = {v["expected"] for v in labels.values()}
    assert verdicts <= {"Blocked", "Needs review", "Clean", "Could not verify"}
    # A mix, not all-attack: both a Clean and a Blocked must be present, or it tests nothing.
    assert "Clean" in verdicts and "Blocked" in verdicts


def test_every_label_has_a_rationale():
    labels = json.loads(LABELS.read_text(encoding="utf-8"))["cases"]
    for cid, v in labels.items():
        assert v.get("rationale") and len(v["rationale"]) > 10, f"{cid} has no rationale"


def test_the_labels_file_records_that_they_were_frozen_blind():
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    note = (labels.get("note") or "").lower()
    assert "blind" in note or "before any tool run" in note
