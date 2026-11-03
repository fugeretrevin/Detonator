"""Evidence manifest: one signable record binding a verdict to everything it rests on.

The behavioural SBOM (`brain/sbom.py`) signs *what a package did*. A reviewer or researcher
checking a decision needs the rest of the chain: which head and base commit, which sandbox
image and Chamber build, which sensor policies, which exact telemetry, which policy, which
model, and whether the observation was trustworthy enough to rely on. This record ties those
together so a single signature covers the whole provenance of one run.

**It asserts what was observed, never that the run succeeded.** The danger an independent audit
named is signing a success assertion when the sensor was blind. This record cannot do that: its
`sufficiency` field is computed by the *same* `brain.verdict.unverified_reason` that gates a
trustworthy "Clean", so a run whose witness failed produces an `inconclusive` manifest that says
so, and the signature then attests honestly to an inconclusive result. A signature proves
origin and integrity under the signing key; it never proves completeness or safety.

**Do not sign before every digest is known.** `telemetry_sha256` and `derived_report_sha256`
pin the raw evidence and the rendered report. A manifest built before the report exists carries
`derived_report_sha256 = None`; sign it then and the signature cannot later be made to cover a
report. Build the manifest after the material it describes is final.

Reuses the Ed25519 primitives in `brain/sbom.py` (`canonical_json`, `sign`, `verify`) rather
than a second signing path. The SBOM and the manifest are different *purposes* under possibly
different keys, which `key_purpose` records, but the cryptography is one implementation.

    python -m brain.evidence_manifest verify <manifest>.json <public_key>.pem
"""

import hashlib
import json
from dataclasses import asdict, dataclass

from brain import sbom
from brain.verdict import unverified_reason
from shared.contract import DetonateResult

SCHEMA = "pr-detonator/evidence-manifest@1"


def telemetry_digest(result: DetonateResult) -> str:
    """sha256 of the telemetry in canonical form. Uses pydantic's own serialization so the
    bytes are stable across runs for identical observations, excluding the decoy values (which
    are per-run secrets and must not leak into a shareable record)."""
    body = result.model_dump(mode="json", exclude={"decoys"})
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass(frozen=True)
class EvidenceManifest:
    """Every field a reader needs to know *what exactly* a verdict was computed from.

    `sufficiency` is `verified` only when `unverified_reason` found no failed precondition; the
    reason is carried verbatim otherwise so the manifest explains its own inconclusiveness.
    None marks a fact not available at build time (an older Chamber, a report not yet rendered),
    never a fact asserted as false.
    """

    schema_version: str
    job_id: str
    # Binding: exactly which revision was assessed.
    repo_commit_sha: str
    base_commit_sha: str | None
    # Provenance of the machinery that observed it.
    sandbox_image_digest: str | None
    chamber_build_sha: str | None
    sensor_policy_hashes: dict[str, str]
    # The observation and whether it can be trusted.
    telemetry_sha256: str
    install_status: str
    install_exit_code: int | None
    telemetry_truncated: bool
    witness_pre_seen: bool | None
    witness_post_seen: bool | None
    sufficiency: str  # "verified" | "inconclusive"
    sufficiency_reason: str  # "" when verified
    # What interpreted it and under what policy.
    model_id: str | None
    policy_sha256: str | None
    derived_report_sha256: str | None
    verdict_title: str | None
    verdict_conclusion: str | None

    def to_dict(self) -> dict:
        return asdict(self)


def policy_digest(policy_source: str | None) -> str | None:
    """sha256 of the raw `.github/detonator.yml` text, or None when the repo set no policy."""
    if policy_source is None:
        return None
    return hashlib.sha256(policy_source.encode()).hexdigest()


def build_manifest(
    result: DetonateResult,
    *,
    repo_commit_sha: str,
    base_commit_sha: str | None = None,
    sandbox_image_digest: str | None = None,
    chamber_build_sha: str | None = None,
    sensor_policy_hashes: dict[str, str] | None = None,
    model_id: str | None = None,
    policy_sha256: str | None = None,
    derived_report_sha256: str | None = None,
    verdict_title: str | None = None,
    verdict_conclusion: str | None = None,
) -> EvidenceManifest:
    """Assemble the manifest from a finished run. Computes `sufficiency` from the same logic
    that gates a trustworthy Clean, so the two can never disagree."""
    reason = unverified_reason(result)
    witness = result.sensor
    return EvidenceManifest(
        schema_version=SCHEMA,
        job_id=result.job_id,
        repo_commit_sha=repo_commit_sha,
        base_commit_sha=base_commit_sha,
        sandbox_image_digest=sandbox_image_digest,
        chamber_build_sha=chamber_build_sha,
        sensor_policy_hashes=dict(sorted((sensor_policy_hashes or {}).items())),
        telemetry_sha256=telemetry_digest(result),
        install_status=result.status,
        install_exit_code=result.exit_code,
        telemetry_truncated=result.truncated,
        witness_pre_seen=witness.pre_seen if witness else None,
        witness_post_seen=witness.post_seen if witness else None,
        sufficiency="verified" if not reason else "inconclusive",
        sufficiency_reason=reason,
        model_id=model_id,
        policy_sha256=policy_sha256,
        derived_report_sha256=derived_report_sha256,
        verdict_title=verdict_title,
        verdict_conclusion=verdict_conclusion,
    )


def sign_manifest(manifest: EvidenceManifest, private_key_pem: bytes) -> dict:
    """Sign the manifest's canonical bytes. Records the key's *purpose* so a verifier can refuse
    a behaviour-SBOM key presented as an evidence-receipt key, and vice versa."""
    record = {**manifest.to_dict(), "key_purpose": "evidence-receipt"}
    return sbom.sign(record, private_key_pem)


def verify_manifest(record: dict, public_key_pem: bytes) -> bool:
    """True only if the signature matches these exact bytes under this key *and* the record is
    an evidence receipt (not a behaviour SBOM signed with the same key)."""
    if record.get("key_purpose") != "evidence-receipt":
        return False
    if record.get("schema_version") != SCHEMA:
        return False
    return sbom.verify(record, public_key_pem)


def _main(argv: list[str]) -> int:
    from pathlib import Path

    if len(argv) == 3 and argv[0] == "verify":
        record = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        ok = verify_manifest(record, Path(argv[2]).read_bytes())
        suff = record.get("sufficiency", "?")
        reason = record.get("sufficiency_reason") or "none"
        print(f"{'OK  ' if ok else 'FAIL'} job={record.get('job_id')} "
              f"head={str(record.get('repo_commit_sha'))[:12]} sufficiency={suff} "
              f"({reason})")  # fmt: skip
        # A valid signature on an inconclusive manifest is still exit 0: the signature is sound,
        # and the manifest truthfully says the observation was insufficient. Signature failure
        # is the only non-zero exit.
        return 0 if ok else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    import sys

    sys.exit(_main(sys.argv[1:]))
