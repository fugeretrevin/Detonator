"""Write the blind corpus payloads into a demo-repo checkout plus a Chamber manifest.

The blind corpus (`eval/blind_corpus.py`) is held-out and not part of the main `CASES`, so it
materializes separately. Same shape as `eval/materialize.py`: payloads land under
`payloads/<id>/`, and the manifest is the `[{id, command}]` the Chamber runner consumes.

    python -m eval.materialize_blind <checkout-or-staging-dir> <manifest.json>

Run against a staging directory first to review exactly what would be pushed to the public
demo repo — these are attack-shaped fixtures, so a human should see them before they go public.
"""

import json
import sys
from pathlib import Path

from eval.blind_corpus import BLIND_CORPUS


def main(checkout: Path, manifest: Path) -> None:
    for case in BLIND_CORPUS:
        for name, data in case.payload_files().items():
            dest = checkout / "payloads" / case.id / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
    manifest.write_text(
        json.dumps([{"id": c.id, "command": c.command} for c in BLIND_CORPUS], indent=1),
        encoding="utf-8",
    )
    print(f"materialized {len(BLIND_CORPUS)} blind cases under {checkout / 'payloads'}")
    print(f"manifest written to {manifest}")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
