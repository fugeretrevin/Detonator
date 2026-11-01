"""Run the Modal CLI with TLS verified against the OS trust store instead of certifi.

Needed on machines where antivirus (e.g. Norton Web Shield) re-signs TLS with a root that
Windows trusts but certifi does not. Usage: `python scripts/modal_cli.py deploy -m brain.app`
"""

import sys

import truststore

truststore.inject_into_ssl()

from modal.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.argv[0] = "modal"
    sys.exit(main())
