# Behavioral SBOM — signed, per-version records of what packages do at install

A lockfile pins **bytes**. It says nothing about behavior, which is why a compromised release
of a dependency you already trust sails through review. These records pin **behavior**: for
one exact `package@version`, what it actually did when installed in a kernel-traced sandbox.

The 73 records here are the packages from the [registry sweep](../SWEEP.md) that installed
cleanly — real packages published to npm minutes before we ran them, at pinned versions.

## What a record contains

```json
{
  "schema": "pr-detonator/behavior-record@1",
  "package": "cfn-idle-cost-linux-x64",
  "version": "1.7.3",
  "install": { "status": "completed", "exit_code": 0, "ran_install_scripts": false },
  "observed": {
    "hosts": ["registry.npmjs.org"],
    "dns_queries": ["registry.npmjs.org"],
    "binaries_outside_system_paths": [],
    "install_scripts": [],
    "credential_files_opened": ["/home/runner/.npmrc"],
    "blocked_non_tcp_egress": [],
    "telemetry_truncated": false
  },
  "provenance": { "detonated_at": "…", "detector_commit": "…", "sandbox": "…" },
  "signature": { "algorithm": "ed25519", "sha256": "…", "value": "…" }
}
```

`credential_files_opened` listing `~/.npmrc` is normal — that's npm reading its own config.
It's recorded because *who* reads a credential file is the interesting part, and the rule that
acts on it ignores npm itself.

## Verify one

```
python -m brain.sbom verify eval/sbom/<record>.json eval/sbom/public_key.pem
```

Records are **canonical JSON** (sorted keys, no insignificant whitespace), so identical
observed behavior always yields identical bytes and therefore the same sha256. The Ed25519
signature covers those bytes, excluding the signature field itself — so any edit to the
observed behavior invalidates it. There's a test that proves tampering fails verification.

**Key handling:** only the public key is in this repository. The demo records were signed with
a key held outside the tree; in production the private key would live in a Modal secret that
only the Brain can read. No private key is ever committed.

## Why this is the interesting direction

`diff_records()` in `brain/sbom.py` turns two versions into a behavior delta — *"4.2.1 added a
connection to a raw IP and a new install script"*. That is the alerting signal for the
registry-scale watch in the roadmap: detonate every new release of the top packages, compare
to the previous version's record, and alert when behavior changes. An account-takeover release
changes behavior even when the code looks plausible, which is exactly how Shai-Hulud spread.
