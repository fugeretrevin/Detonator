import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from brain.sbom import SCHEMA, build_record, canonical_json, diff_records, digest, sign, verify
from shared.contract import ConnectEvent, DetonateResult, ExecEvent, ExecutedScript, FileEvent

SBOM_DIR = Path(__file__).parent.parent / "eval/sbom"


def keypair() -> tuple[bytes, bytes]:
    k = Ed25519PrivateKey.generate()
    return (
        k.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),  # fmt: skip
        k.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),  # fmt: skip
    )


def result(host="cdn.example", scripts=(), files=(), proto="tcp") -> DetonateResult:
    conn = ConnectEvent(ts="t", pid=1, binary="/usr/local/bin/node", daddr="93.1.1.1",
                        dport=443, family="AF_INET", resolved_domain=host,
                        protocol=proto)  # fmt: skip
    ex = ExecEvent(ts="t", pid=2, ppid=1, binary="/work/node_modules/p/bin/tool", args="",
                   parent_binary="sh", uid=10001, cwd="/work")  # fmt: skip
    return DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=2.5,
                          exec_events=[ex], connect_events=[conn], dns_queries=[],
                          stdout_tail="", stderr_tail="", executed_scripts=list(scripts),
                          file_events=list(files))  # fmt: skip


def record_for(res: DetonateResult, version="1.0.0") -> dict:
    return build_record("demo-pkg", version, res, detector_commit="abc1234",
                        detonated_at="2026-11-02T00:00:00Z")  # fmt: skip


def test_record_captures_observed_behavior():
    script = ExecutedScript(path="/work/node_modules/p/install.js", package="p",
                            sha256="a" * 64, content="x")  # fmt: skip
    bait = FileEvent(ts="t", pid=2, binary="/usr/local/bin/node", path="/home/runner/.npmrc")
    rec = record_for(result(scripts=[script], files=[bait]))
    assert rec["schema"] == SCHEMA and rec["package"] == "demo-pkg"
    assert rec["observed"]["hosts"] == ["cdn.example"]
    assert rec["observed"]["install_scripts"] == [
        {"path": "/work/node_modules/p/install.js", "package": "p", "sha256": "a" * 64}
    ]
    assert rec["observed"]["credential_files_opened"] == ["/home/runner/.npmrc"]
    assert rec["observed"]["binaries_outside_system_paths"] == ["/work/node_modules/p/bin/tool"]
    assert rec["install"]["ran_install_scripts"] is True


def test_canonical_json_is_stable_regardless_of_key_order():
    rec = record_for(result())
    shuffled = dict(reversed(list(rec.items())))
    assert canonical_json(rec) == canonical_json(shuffled)
    assert digest(rec) == digest(shuffled)


def test_signature_round_trips_and_excludes_itself():
    priv, pub = keypair()
    signed = sign(record_for(result()), priv)
    assert verify(signed, pub)
    # signing is over the body, so the signature field doesn't feed its own digest
    assert canonical_json(signed) == canonical_json(record_for(result()))


def test_tampering_breaks_verification():
    priv, pub = keypair()
    signed = sign(record_for(result()), priv)
    tampered = json.loads(json.dumps(signed))
    tampered["observed"]["hosts"] = ["evil.example"]
    assert not verify(tampered, pub)


def test_wrong_key_and_unsigned_record_fail():
    priv, _ = keypair()
    _, other_pub = keypair()
    assert not verify(sign(record_for(result()), priv), other_pub)
    assert not verify(record_for(result()), other_pub)


def test_non_tcp_egress_recorded_separately_from_hosts():
    rec = record_for(result(host=None, proto="udp"))
    assert rec["observed"]["hosts"] == []
    assert rec["observed"]["blocked_non_tcp_egress"] == ["udp:93.1.1.1:443"]


def test_diff_surfaces_a_new_host_and_changed_script():
    old = record_for(result(), version="1.0.0")
    new_script = ExecutedScript(path="/work/node_modules/p/install.js", package="p",
                                sha256="b" * 64, content="y")  # fmt: skip
    conn = ConnectEvent(ts="t", pid=1, binary="/usr/local/bin/node", daddr="203.0.113.10",
                        dport=4444, family="AF_INET", resolved_domain=None)  # fmt: skip
    changed = result(scripts=[new_script])
    changed = changed.model_copy(update={"connect_events": [*changed.connect_events, conn]})
    new = record_for(changed, version="1.0.1")
    d = diff_records(old, new)
    assert "203.0.113.10" in d["added_hosts"]
    assert d["changed_install_scripts"] == ["b" * 64]


# --- the committed records must actually verify against the committed public key ---


def test_committed_records_verify():
    pub = (SBOM_DIR / "public_key.pem").read_bytes()
    files = [p for p in SBOM_DIR.glob("*.json") if p.name != "index.json"]
    assert files, "no committed behavior records"
    for path in files[:15]:
        assert verify(json.loads(path.read_text()), pub), path.name


def test_no_private_key_committed():
    assert not list(SBOM_DIR.glob("*private*"))
    assert "PRIVATE KEY" not in (SBOM_DIR / "public_key.pem").read_text()
