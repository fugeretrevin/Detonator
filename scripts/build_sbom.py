"""Build signed behavioral SBOM records from recorded detonations.

  python scripts/build_sbom.py <results-dir> <names.json> <out-dir> [private_key.pem]

<names.json> maps result id -> {name, version} (the registry sweep writes it). Without a key
the records are written unsigned but still carry their canonical sha256.

The signing key never belongs in this repository: for the committed demo records it lives
outside the tree, and in production it would be a Modal secret held only by the Brain.
"""

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from brain.sbom import build_record, sign  # noqa: E402
from shared.contract import DetonateResult  # noqa: E402


def detector_commit() -> str:
    out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                         capture_output=True, text=True, check=True)  # fmt: skip
    return out.stdout.strip()


def main(results_dir: str, names_path: str, out_dir: str, key_path: str | None = None) -> None:
    names = json.loads(Path(names_path).read_text())
    key = Path(key_path).read_bytes() if key_path else None
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    commit = detector_commit()
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    written = 0
    for result_id, meta in names.items():
        path = Path(results_dir) / f"{result_id}.json"
        if not path.exists():
            continue
        result = DetonateResult.model_validate_json(path.read_text())
        # Only record versions that actually installed: a record of "npm refused this on
        # linux-x64" describes our platform, not the package's behavior.
        if result.status != "completed" or result.exit_code:
            continue
        record = build_record(meta["name"], meta["version"], result,
                              detector_commit=commit, detonated_at=now)  # fmt: skip
        if key:
            record = sign(record, key)
        safe = f"{meta['name']}@{meta['version']}".replace("@", "_at_").replace("/", "_")
        (out / f"{safe}.json").write_text(json.dumps(record, indent=1, sort_keys=True))
        written += 1
    print(f"wrote {written} behavior records to {out}{' (signed)' if key else ' (unsigned)'}")
    index = sorted(p.name for p in out.glob("*.json") if p.name != "index.json")
    (out / "index.json").write_text(json.dumps(
        {"schema": "pr-detonator/behavior-index@1", "detector_commit": commit,
         "records": index}, indent=1))  # fmt: skip


if __name__ == "__main__":
    main(*sys.argv[1:5])
