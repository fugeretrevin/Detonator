"""A0 acceptance: mint an installation token and list the demo repo's open PRs.

Reads GITHUB_APP_ID, GITHUB_PRIVATE_KEY or GITHUB_PRIVATE_KEY_PATH, GITHUB_INSTALLATION_ID
(optional; auto-detected from DEMO_REPO), and DEMO_REPO=owner/repo from the environment or .env.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from brain.github_client import GitHubClient  # noqa: E402


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def main() -> None:
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    key = os.environ.get("GITHUB_PRIVATE_KEY")
    if not key and os.environ.get("GITHUB_PRIVATE_KEY_PATH"):
        key = Path(os.environ["GITHUB_PRIVATE_KEY_PATH"]).read_text(encoding="utf-8")
    if not key or not os.environ.get("GITHUB_APP_ID") or not os.environ.get("DEMO_REPO"):
        sys.exit("need GITHUB_APP_ID, GITHUB_PRIVATE_KEY(_PATH) and DEMO_REPO")

    owner, repo = os.environ["DEMO_REPO"].split("/", 1)
    gh = GitHubClient(os.environ["GITHUB_APP_ID"], key)

    installation_id = os.environ.get("GITHUB_INSTALLATION_ID")
    if not installation_id:
        resp = gh._http.get(
            f"/repos/{owner}/{repo}/installation",
            headers={"Authorization": f"Bearer {gh.app_jwt()}"},
        )
        resp.raise_for_status()
        installation_id = resp.json()["id"]
    installation_id = int(installation_id)
    print(f"installation id: {installation_id}")

    gh.installation_token(installation_id)
    print("minted installation token: OK")
    prs = gh.list_open_prs(installation_id, owner, repo)
    print(f"{len(prs)} open PR(s) on {owner}/{repo}")
    for pr in prs:
        print(f"  #{pr['number']} {pr['title']!r} head={pr['head']['sha'][:8]}")


if __name__ == "__main__":
    main()
