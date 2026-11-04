"""Write the validation set payloads into a checkout plus a Chamber manifest.

Mirrors `eval/materialize_blind.py` for the W12 validation set (`eval/validation_set.py`): a
held-out, blind-written set whose verdicts were frozen in `eval/validation_labels.json` before
any tool run. Payloads land under `payloads/<id>/`; the manifest is the `[{id, command}]` the
Chamber runner consumes.

    python -m eval.materialize_validation <checkout-or-staging-dir> <manifest.json>
"""

import json
import sys
from pathlib import Path

from eval.validation_set import VALIDATION_SET


def main(checkout: Path, manifest: Path) -> None:
    for case in VALIDATION_SET:
        for name, data in case.payload_files().items():
            dest = checkout / "payloads" / case.id / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
    manifest.write_text(
        json.dumps([{"id": c.id, "command": c.command} for c in VALIDATION_SET], indent=1),
        encoding="utf-8",
    )
    print(f"materialized {len(VALIDATION_SET)} validation cases under {checkout / 'payloads'}")
    print(f"manifest written to {manifest}")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
