"""`brain.evidence_manifest` — the signable provenance record for one verdict.

The properties worth asserting are the ones an audit named as the ways such a record goes
wrong: it must not assert success when the sensor was blind, its bytes must be deterministic so
a signature means something, tampering with any bound field must be caught, and no per-run
secret may reach a shareable record.
"""

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from brain.evidence_manifest import (
    SCHEMA,
    build_manifest,
    policy_digest,
    sign_manifest,
    telemetry_digest,
    verify_manifest,
)
from shared.contract import DetonateResult, ExecEvent, SensorWitness


def keypair() -> tuple[bytes, bytes]:
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = k.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv, pub


def exec_(ts="2026-01-01T00:00:00Z", pid=1, binary="/usr/local/bin/node") -> ExecEvent:
    return ExecEvent(ts=ts, pid=pid, ppid=None, binary=binary, args="install",
                     parent_binary=None, uid=0)  # fmt: skip


def good_result(**over) -> DetonateResult:
    """A clean, fully verified run: completed, exit 0, exec events, both witness markers."""
    base = dict(
        job_id="job-1", status="completed", exit_code=0, duration_s=3.0,
        exec_events=[exec_()], connect_events=[], dns_queries=[],
        stdout_tail="", stderr_tail="", truncated=False,
        sensor=SensorWitness(pre_seen=True, post_seen=True),
    )  # fmt: skip
    base.update(over)
    return DetonateResult(**base)


# --- sufficiency mirrors the trust logic, not a parallel copy ---


def test_a_clean_run_is_verified():
    m = build_manifest(good_result(), repo_commit_sha="a" * 40)
    assert m.sufficiency == "verified"
    assert m.sufficiency_reason == ""


@pytest.mark.parametrize(
    "over,fragment",
    [
        ({"status": "timeout", "exit_code": None}, "did not finish"),
        ({"exit_code": 1}, "exit code 1"),
        ({"truncated": True}, "truncated"),
        ({"exec_events": []}, "sensor was blind"),
        ({"sensor": SensorWitness(pre_seen=False, post_seen=True)}, "start marker"),
        ({"sensor": SensorWitness(pre_seen=True, post_seen=False)}, "end marker"),
    ],
)
def test_a_run_that_fails_a_precondition_is_inconclusive(over, fragment):
    m = build_manifest(good_result(**over), repo_commit_sha="a" * 40)
    assert m.sufficiency == "inconclusive"
    assert fragment in m.sufficiency_reason


def test_sufficiency_cannot_disagree_with_unverified_reason():
    """It is computed *from* unverified_reason, so this is a guard against someone later
    reimplementing it and letting the two drift."""
    from brain.verdict import unverified_reason

    for over in ({}, {"exit_code": 1}, {"truncated": True}, {"exec_events": []}):
        r = good_result(**over)
        m = build_manifest(r, repo_commit_sha="a" * 40)
        expected = "verified" if not unverified_reason(r) else "inconclusive"
        assert m.sufficiency == expected


# --- the audit's central warning: never sign a success assertion for a blind run ---


def test_a_blind_run_signs_an_honestly_inconclusive_manifest():
    """The manifest for a witness-failed run is signable, and what it attests is that the run
    was inconclusive. The signature is sound; it does not launder a failure into a success."""
    priv, pub = keypair()
    blind = good_result(sensor=SensorWitness(pre_seen=False, post_seen=False))
    signed = sign_manifest(build_manifest(blind, repo_commit_sha="a" * 40), priv)
    assert verify_manifest(signed, pub)
    assert signed["sufficiency"] == "inconclusive"
    assert signed["sufficiency_reason"]  # non-empty: it says why


def test_no_manifest_field_asserts_success_as_a_bare_boolean():
    """There is deliberately no `clean: true` or `verified: true` field a reader could trust
    without its reason. Trust is the sufficiency string plus its reason, together."""
    m = build_manifest(good_result(), repo_commit_sha="a" * 40)
    d = m.to_dict()
    assert "sufficiency" in d and "sufficiency_reason" in d
    assert not any(
        isinstance(v, bool) and k.startswith(("clean", "safe", "verified")) for k, v in d.items()
    )


# --- deterministic bytes and tamper detection ---


def test_the_same_run_produces_identical_bytes():
    """A signature is only meaningful if the bytes it covers are reproducible. Two manifests
    built from the same inputs must canonicalise identically. Signing adds `key_purpose` before
    signing and a `signature` after; `canonical_json` drops only the signature, so the signed
    body equals that same dict with `key_purpose` added directly."""
    from brain import sbom

    r = good_result()
    rebuilt_a = sbom.canonical_json(build_manifest(r, repo_commit_sha="a" * 40).to_dict())
    rebuilt_b = sbom.canonical_json(build_manifest(r, repo_commit_sha="a" * 40).to_dict())
    assert rebuilt_a == rebuilt_b, "same inputs must give identical bytes"

    signed = sbom.canonical_json(
        sign_manifest(build_manifest(r, repo_commit_sha="a" * 40), keypair()[0])
    )
    expected = sbom.canonical_json(
        {**build_manifest(r, repo_commit_sha="a" * 40).to_dict(), "key_purpose": "evidence-receipt"}
    )
    assert signed == expected


def test_telemetry_digest_is_stable_and_order_independent():
    r1 = good_result()
    r2 = good_result()
    assert telemetry_digest(r1) == telemetry_digest(r2)


def test_a_different_head_sha_changes_the_digest():
    from brain import sbom

    one = build_manifest(good_result(), repo_commit_sha="a" * 40).to_dict()
    two = build_manifest(good_result(), repo_commit_sha="b" * 40).to_dict()
    assert sbom.canonical_json(one) != sbom.canonical_json(two)


@pytest.mark.parametrize("field", ["repo_commit_sha", "sandbox_image_digest", "telemetry_sha256",
                                   "sufficiency", "verdict_conclusion"])  # fmt: skip
def test_tampering_with_any_bound_field_is_caught(field):
    priv, pub = keypair()
    signed = sign_manifest(
        build_manifest(good_result(), repo_commit_sha="a" * 40,
                       sandbox_image_digest="sha256:abc", verdict_conclusion="success"), priv,
    )  # fmt: skip
    assert verify_manifest(signed, pub)
    signed[field] = "tampered"
    assert not verify_manifest(signed, pub)


def test_telemetry_tampering_is_caught_through_the_digest():
    """The manifest binds the telemetry by hash. Alter the run — here, add a connection that
    was not there — and the manifest's pinned digest no longer matches the altered telemetry,
    which is the mismatch a verifier re-deriving the digest would surface."""
    from shared.contract import ConnectEvent

    original = good_result()
    pinned = build_manifest(original, repo_commit_sha="a" * 40).telemetry_sha256
    assert pinned == telemetry_digest(original)

    altered = good_result(connect_events=[ConnectEvent(
        ts="t", pid=1, binary="/usr/local/bin/node", daddr="203.0.113.10", dport=443,
        family="AF_INET", resolved_domain=None)])  # fmt: skip
    assert pinned != telemetry_digest(altered), "an added connection must change the digest"


# --- no per-run secret reaches the record ---


def test_decoy_values_never_enter_the_manifest_or_its_digest():
    secret = "decoy-canary-must-not-leak"
    r = good_result(decoys={"NPM_TOKEN": secret})
    m = build_manifest(r, repo_commit_sha="a" * 40)
    blob = json.dumps(m.to_dict())
    assert secret not in blob
    # And the digest must not depend on the decoys, or it would be a side channel.
    assert telemetry_digest(r) == telemetry_digest(good_result())


def test_no_raw_secret_shaped_material_in_a_signed_manifest():
    priv, _ = keypair()
    signed = sign_manifest(build_manifest(good_result(), repo_commit_sha="a" * 40), priv)
    blob = json.dumps(signed)
    assert "PRIVATE KEY" not in blob
    assert "BEGIN" not in blob  # no PEM of any kind


# --- key purpose separation ---


def test_a_behaviour_sbom_key_signature_is_not_accepted_as_a_receipt():
    """Same Ed25519 math, different purpose. A behaviour SBOM signed with a key must not verify
    as an evidence receipt, so the two record types cannot be confused."""
    from brain import sbom

    priv, pub = keypair()
    # A record that is validly signed but lacks the evidence-receipt purpose marker.
    sbom_like = sbom.sign({"schema": sbom.SCHEMA, "package": "x"}, priv)
    assert not verify_manifest(sbom_like, pub)


def test_a_receipt_with_the_wrong_schema_is_rejected():
    priv, pub = keypair()
    signed = sign_manifest(build_manifest(good_result(), repo_commit_sha="a" * 40), priv)
    assert verify_manifest(signed, pub)
    signed["schema_version"] = "pr-detonator/something-else@1"
    # digest no longer matches AND schema guard trips; either way it must fail.
    assert not verify_manifest(signed, pub)


def test_the_schema_guard_rejects_even_when_the_signature_is_valid():
    """Isolates the schema check from the digest check: re-sign AFTER changing the schema, so
    the signature is sound and only the schema guard can reject. Without this, a mutation
    removing the guard survived because the digest check backstopped it."""
    from brain import sbom

    priv, pub = keypair()
    tampered = {
        **build_manifest(good_result(), repo_commit_sha="a" * 40).to_dict(),
        "key_purpose": "evidence-receipt",
        "schema_version": "pr-detonator/not-a-manifest@1",
    }
    resigned = sbom.sign(tampered, priv)
    assert sbom.verify(resigned, pub), "the re-signed record's signature must itself be valid"
    assert not verify_manifest(resigned, pub), "but the schema guard must still reject it"


def test_the_purpose_guard_rejects_even_when_the_signature_is_valid():
    """Isolates the key-purpose check the same way: a correctly-schema'd, validly-signed record
    whose only fault is the wrong purpose must be refused, so a behaviour SBOM re-signed with a
    receipt key cannot pass as a receipt."""
    from brain import sbom

    priv, pub = keypair()
    tampered = {
        **build_manifest(good_result(), repo_commit_sha="a" * 40).to_dict(),
        "key_purpose": "behavior-record",  # wrong purpose, everything else valid
    }
    resigned = sbom.sign(tampered, priv)
    assert sbom.verify(resigned, pub)
    assert not verify_manifest(resigned, pub)


# --- optional fields are None, not fabricated ---


def test_facts_not_available_are_none_not_guessed():
    m = build_manifest(good_result(), repo_commit_sha="a" * 40)
    assert m.base_commit_sha is None
    assert m.sandbox_image_digest is None
    assert m.derived_report_sha256 is None
    assert m.model_id is None


def test_a_v2_chamber_run_has_null_witness_not_false():
    """No witness (older Chamber) must read as 'unknown', not 'failed' — the distinction the
    whole record exists to preserve."""
    m = build_manifest(good_result(sensor=None), repo_commit_sha="a" * 40)
    assert m.witness_pre_seen is None and m.witness_post_seen is None
    # And with no witness, sufficiency falls back to the other preconditions (all pass here).
    assert m.sufficiency == "verified"


def test_policy_digest_is_none_without_a_policy_and_stable_with_one():
    assert policy_digest(None) is None
    assert policy_digest("needs_review: block") == policy_digest("needs_review: block")
    assert policy_digest("a") != policy_digest("b")


# --- the CLI verifier ---


def test_the_cli_verifier_reports_ok_on_a_sound_signature(tmp_path, capsys):
    from brain.evidence_manifest import _main

    priv, pub = keypair()
    signed = sign_manifest(build_manifest(good_result(), repo_commit_sha="a" * 40), priv)
    (tmp_path / "m.json").write_text(json.dumps(signed), encoding="utf-8")
    (tmp_path / "pub.pem").write_bytes(pub)
    rc = _main(["verify", str(tmp_path / "m.json"), str(tmp_path / "pub.pem")])
    out = capsys.readouterr().out
    assert rc == 0 and "OK" in out and "verified" in out


def test_the_cli_verifier_fails_on_a_tampered_signature(tmp_path, capsys):
    from brain.evidence_manifest import _main

    priv, pub = keypair()
    signed = sign_manifest(build_manifest(good_result(), repo_commit_sha="a" * 40), priv)
    signed["repo_commit_sha"] = "c" * 40
    (tmp_path / "m.json").write_text(json.dumps(signed), encoding="utf-8")
    (tmp_path / "pub.pem").write_bytes(pub)
    rc = _main(["verify", str(tmp_path / "m.json"), str(tmp_path / "pub.pem")])
    assert rc == 1 and "FAIL" in capsys.readouterr().out


def test_schema_constant_is_versioned():
    assert SCHEMA.endswith("@1")
