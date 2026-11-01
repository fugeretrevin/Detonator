"""Per-run canary credentials and decoy tools (HARDENING_PLAN P1.2).

The sandbox should look like a developer or CI machine worth robbing: CI env vars, tokens in
the environment and in ~/.npmrc / ~/.aws, and AI/cloud CLIs on PATH. Every value is random
per run and fake; none is ever a real credential, and none is committed. The Brain gets the
values back in the signed result to look for them in what the sandbox did, and redacts them
before anything is shown or posted.
"""

import secrets
import string
from pathlib import Path

DECOY_BIN = "/usr/local/decoy/bin"  # inside the sandbox; prepended to PATH
IMAGE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"  # node:20-slim
CI_ENV = {"CI": "true", "GITHUB_ACTIONS": "true"}

_ALNUM = string.ascii_letters + string.digits
_UPPER = string.ascii_uppercase + string.digits


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def make_decoys() -> dict[str, str]:
    """Fresh fake values, shaped like the real thing so a payload's regex accepts them."""
    return {
        "GITHUB_TOKEN": "ghp_" + _rand(_ALNUM, 36),
        "NPM_TOKEN": "npm_" + _rand(_ALNUM, 36),
        "AWS_ACCESS_KEY_ID": "AKIA" + _rand(_UPPER, 16),
        "AWS_SECRET_ACCESS_KEY": _rand(_ALNUM + "/+", 40),
        "NPMRC_TOKEN": "npm_" + _rand(_ALNUM, 36),
    }


def decoy_env(decoys: dict[str, str]) -> dict[str, str]:
    env = {k: v for k, v in decoys.items() if k != "NPMRC_TOKEN"}
    return {**env, **CI_ENV, "PATH": f"{DECOY_BIN}:{IMAGE_PATH}"}


def write_bait_files(directory: Path, decoys: dict[str, str]) -> dict[str, Path]:
    """Per-run bait whose content carries this run's decoys. Returns bait name -> file."""
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o755)
    files = {
        # Scoped to GitHub Packages: npm never sends it to registry.npmjs.org.
        "npmrc": "# not a real credential\n@detonator-bait:registry=https://npm.pkg.github.com/\n"
                 f"//npm.pkg.github.com/:_authToken={decoys['NPMRC_TOKEN']}\n",
        "aws_credentials": "# not a real credential\n[default]\n"
                           f"aws_access_key_id = {decoys['AWS_ACCESS_KEY_ID']}\n"
                           f"aws_secret_access_key = {decoys['AWS_SECRET_ACCESS_KEY']}\n",
    }  # fmt: skip
    out = {}
    for name, text in files.items():
        path = directory / name
        path.write_text(text)
        path.chmod(0o644)
        out[name] = path
    return out
