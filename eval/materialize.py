"""Write payload packages into a demo-repo checkout and a manifest for the Chamber runner.

python -m eval.materialize <demo-repo-checkout> <manifest.json>
"""

import json
import sys
from pathlib import Path

from eval.cases import CASES, INCIDENTS, MALICIOUS, REDTEAM


def main(checkout: Path, manifest: Path) -> None:
    for case in MALICIOUS + INCIDENTS + REDTEAM:
        for name, data in case.payload_files().items():
            dest = checkout / "payloads" / case.id / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
    manifest.write_text(
        json.dumps([{"id": c.id, "command": c.command} for c in CASES.values()], indent=1)
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
