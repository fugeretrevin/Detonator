import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from brain.sbom import SCHEMA, build_record, canonical_json, diff_records, digest, sign, verify
from shared.contract import ConnectEvent, DetonateResult, ExecEvent, ExecutedScript, FileEvent

SBOM_DIR = Path(__file__).parent.parent / "eval/sbom"


def keypair() -> tuple[bytes, bytes]:
    k = Ed25519PrivateKey.generate()
    return (
        k.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),  # fmt: skip
        k.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),  # fmt: skip
    )


def result(host="cdn.example", scripts=(), files=(), proto="tcp") -> DetonateResult:
    conn = ConnectEvent(ts="t", pid=1, binary="/usr/local/bin/node", daddr="93.1.1.1",
                        dport=443, family="AF_INET", resolved_domain=host,
                        protocol=proto)  # fmt: skip
    ex = ExecEvent(ts="t", pid=2, ppid=1, binary="/work/node_modules/p/bin/tool", args="",
                   parent_binary="sh", uid=10001, cwd="/work")  # fmt: skip
    return DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=2.5,
                          exec_events=[ex], connect_events=[conn], dns_queries=[],
                          stdout_tail="", stderr_tail="", executed_scripts=list(scripts),
                          file_events=list(files))  # fmt: skip


def record_for(res: DetonateResult, version="1.0.0") -> dict:
    return build_record("demo-pkg", version, res, detector_commit="abc1234",
                        detonated_at="2026-11-02T00:00:00Z")  # fmt: skip


def test_record_captures_observed_behavior():
    script = ExecutedScript(path="/work/node_modules/p/install.js", package="p",
                            sha256="a" * 64, content="x")  # fmt: skip
    bait = FileEvent(ts="t", pid=2, binary="/usr/local/bin/node", path="/home/runner/.npmrc")
    rec = record_for(result(scripts=[script], files=[bait]))
    assert rec["schema"] == SCHEMA and rec["package"] == "demo-pkg"
    assert rec["observed"]["hosts"] == ["cdn.example"]
    assert rec["observed"]["install_scripts"] == [
        {"path": "/work/node_modules/p/install.js", "package": "p", "sha256": "a" * 64}
    ]
    assert rec["observed"]["credential_files_opened"] == ["/home/runner/.npmrc"]
    assert rec["observed"]["binaries_outside_system_paths"] == ["/work/node_modules/p/bin/tool"]
    assert rec["install"]["ran_install_scripts"] is True


def test_canonical_json_is_stable_regardless_of_key_order():
    rec = record_for(result())
    shuffled = dict(reversed(list(rec.items())))
    assert canonical_json(rec) == canonical_json(shuffled)
    assert digest(rec) == digest(shuffled)


def test_signature_round_trips_and_excludes_itself():
    priv, pub = keypair()
    signed = sign(record_for(result()), priv)
    assert verify(signed, pub)
    # signing is over the body, so the signature field doesn't feed its own digest
    assert canonical_json(signed) == canonical_json(record_for(result()))


def test_tampering_breaks_verification():
    priv, pub = keypair()
    signed = sign(record_for(result()), priv)
    tampered = json.loads(json.dumps(signed))
    tampered["observed"]["hosts"] = ["evil.example"]
    assert not verify(tampered, pub)


def test_wrong_key_and_unsigned_record_fail():
    priv, _ = keypair()
    _, other_pub = keypair()
    assert not verify(sign(record_for(result()), priv), other_pub)
    assert not verify(record_for(result()), other_pub)


def test_non_tcp_egress_recorded_separately_from_hosts():
    rec = record_for(result(host=None, proto="udp"))
    assert rec["observed"]["hosts"] == []
    assert rec["observed"]["blocked_non_tcp_egress"] == ["udp:93.1.1.1:443"]


def test_diff_surfaces_a_new_host_and_changed_script():
    old = record_for(result(), version="1.0.0")
    new_script = ExecutedScript(path="/work/node_modules/p/install.js", package="p",
                                sha256="b" * 64, content="y")  # fmt: skip
    conn = ConnectEvent(ts="t", pid=1, binary="/usr/local/bin/node", daddr="203.0.113.10",
                        dport=4444, family="AF_INET", resolved_domain=None)  # fmt: skip
    changed = result(scripts=[new_script])
    changed = changed.model_copy(update={"connect_events": [*changed.connect_events, conn]})
    new = record_for(changed, version="1.0.1")
    d = diff_records(old, new)
    assert "203.0.113.10" in d["added_hosts"]
    assert d["changed_install_scripts"] == ["b" * 64]


# --- the committed records must actually verify against the committed public key ---


def test_committed_records_verify():
    pub = (SBOM_DIR / "public_key.pem").read_bytes()
    files = [p for p in SBOM_DIR.glob("*.json") if p.name != "index.json"]
    assert files, "no committed behavior records"
    for path in files[:15]:
        assert verify(json.loads(path.read_text()), pub), path.name


def test_no_private_key_committed():
    assert not list(SBOM_DIR.glob("*private*"))
    assert "PRIVATE KEY" not in (SBOM_DIR / "public_key.pem").read_text()


# --- version delta ---

from brain.report import esc  # noqa: E402
from brain.sbom import behavior_delta, render_delta, terminal_safe  # noqa: E402

ENV = {"sandbox_image": "sha256:aaa", "node": "20.19.0", "npm": "10.8.2",
       "command": "npm install --no-audit --no-fund"}  # fmt: skip


def rec(res: DetonateResult, version: str, env=ENV, commit="abc1234") -> dict:
    return build_record("color-helper", version, res, detector_commit=commit,
                        detonated_at="2026-11-02T00:00:00Z", environment=env)  # fmt: skip


def script(sha: str, path="/work/node_modules/color-helper/install.js") -> ExecutedScript:
    return ExecutedScript(path=path, package="color-helper", sha256=sha, content="x")


def bad_release() -> DetonateResult:
    raw = ConnectEvent(ts="t", pid=1, binary="/usr/local/bin/node", daddr="203.0.113.10",
                       dport=4444, family="AF_INET", resolved_domain=None)  # fmt: skip
    dropped = ExecEvent(ts="t", pid=3, ppid=1, binary="/tmp/x/miner", args="", parent_binary="sh",
                        uid=10001, cwd="/work")  # fmt: skip
    cred = FileEvent(
        ts="t", pid=1, binary="/usr/local/bin/node", path="/home/runner/.aws/credentials"
    )
    res = result(scripts=[script("b" * 64)], files=[cred])
    return res.model_copy(update={"connect_events": [*res.connect_events, raw],
                                  "exec_events": [*res.exec_events, dropped]})  # fmt: skip


def test_bad_release_is_flagged_for_attention_but_not_called_malicious():
    d = behavior_delta(
        rec(result(scripts=[script("a" * 64)]), "1.0.0"), rec(bad_release(), "1.0.1")
    )
    assert d.comparability == "comparable" and d.reasons == []
    joined = " ".join(d.attention)
    for want in ("new raw IP contacted at install: 203.0.113.10",
                 "temp/home directory: /tmp/x/miner",
                 "new credential file opened: /home/runner/.aws/credentials",
                 "install script changed: /work/node_modules/color-helper/install.js"):  # fmt: skip
        assert want in joined
    assert d.changed_scripts == [{"path": "/work/node_modules/color-helper/install.js",
                                  "old_sha256": "a" * 64, "new_sha256": "b" * 64}]  # fmt: skip
    md = render_delta(d)
    assert "malicious" not in md.lower() and "not a verdict" in md


def test_same_behavior_is_reported_unchanged():
    same = result(scripts=[script("a" * 64)])
    d = behavior_delta(rec(same, "1.0.0"), rec(same, "1.0.1"))
    assert d.unchanged and d.attention == []
    assert "No change in observed install-time behavior" in render_delta(d)


def test_new_vendor_cdn_is_a_change_not_an_alarm_if_allowlisted():
    d = behavior_delta(
        rec(result(host="registry.npmjs.org"), "1"), rec(result(host="github.com"), "2")
    )
    assert d.changes["added_hosts"] == ["github.com"] and d.attention == []


def test_environment_mismatch_is_partially_comparable():
    newer_npm = {**ENV, "npm": "11.0.0"}
    d = behavior_delta(rec(result(), "1"), rec(result(), "2", env=newer_npm))
    assert d.comparability == "partially_comparable"
    assert any("npm differs" in r for r in d.reasons)


def test_missing_environment_or_detector_change_is_partially_comparable():
    d = behavior_delta(rec(result(), "1", env=None), rec(result(), "2", commit="def5678"))
    assert d.comparability == "partially_comparable" and len(d.reasons) == 2


def test_failed_or_truncated_install_is_incomparable():
    failed = result().model_copy(update={"exit_code": 1})
    truncated = result().model_copy(update={"truncated": True})
    for broken in (failed, truncated):
        d = behavior_delta(rec(result(), "1"), rec(broken, "2"))
        assert d.comparability == "incomparable"
        assert "Not compared" in render_delta(d)


def test_bad_signature_makes_it_incomparable():
    priv, pub = keypair()
    old, new = sign(rec(result(), "1"), priv), sign(rec(result(), "2"), priv)
    assert behavior_delta(old, new, pub).signatures == {"old": True, "new": True}
    tampered = {**new, "version": "2-evil"}
    d = behavior_delta(old, tampered, pub)
    assert d.signatures["new"] is False and d.comparability == "incomparable"


def test_environment_is_optional_and_old_records_are_byte_identical():
    assert "environment" not in rec(result(), "1", env=None)
    assert rec(result(), "1")["environment"] == dict(sorted(ENV.items()))
    # build_record without environment = the schema the committed records were signed under
    assert test_committed_records_verify() is None


def test_rendered_values_are_escaped():
    hostile = result(host="evil.example|<img src=x>`")
    d = behavior_delta(rec(result(), "1"), rec(hostile, "2"))
    md = render_delta(d)
    assert "<img" not in md and esc("evil.example|<img src=x>`", 160) in md


# --- the CLI renders for a terminal, not for a GitHub comment ----------------------------
#
# `python -m brain.sbom diff` is the live command the demo script ends on, and it was printing
# entity-encoded markdown to the console: `color&#45;helper&#64;1&#46;0&#46;0`. Correct for a PR
# comment, unreadable on a terminal, and it looked like a bug on camera. The escaping could not
# simply be dropped, because the values still come from a sandbox that ran untrusted code - a
# terminal just has a different threat than HTML does.


def test_the_cli_output_is_readable_rather_than_entity_encoded():
    d = behavior_delta(
        rec(result(scripts=[script("a" * 64)]), "1.0.0"), rec(bad_release(), "1.0.1")
    )
    plain = render_delta(d, plain=True)
    assert "color-helper@1.0.0 → color-helper@1.0.1" in plain
    assert "203.0.113.10" in plain
    assert "&#" not in plain, "entity encoding is unreadable on a console"


def test_the_github_comment_path_is_untouched_by_the_cli_change():
    """The regression that would matter: `plain` must default to off, so nothing rendering
    into a PR comment can lose entity encoding by forgetting an argument."""
    hostile = result(host="evil.example|<img src=x>`")
    d = behavior_delta(rec(result(), "1"), rec(hostile, "2"))
    assert render_delta(d) == render_delta(d, plain=False)
    assert "&#" in render_delta(d) and "<img" not in render_delta(d)


@pytest.mark.parametrize(
    "hostile,why",
    [
        ("\x1b[2J\x1b[Hcleared your screen", "ANSI escape could repaint the terminal"),
        ("\x1b]0;fake title\x07", "OSC sequence could set the window title"),
        ("evil\rregistry.npmjs.org", "carriage return could overwrite the line just printed"),
        ("moc.reka‮catta", "bidi override visually reverses the hostname"),
        ("a\x08\x08\x08safe", "backspaces could rub out what we printed"),
        ("null\x00byte", "NUL can truncate in downstream consumers"),
    ],
)
def test_terminal_control_sequences_in_record_values_are_neutralized(hostile, why):
    """A package name is attacker-chosen. On a console the danger is not markup but control
    characters, so `terminal_safe` escapes every Unicode `C*` category rather than matching
    ANSI patterns - which also covers the bidi override, where an ANSI regex would not."""
    out = terminal_safe(hostile)
    assert "\x1b" not in out and "\r" not in out and "\x00" not in out and "\x08" not in out
    assert "‮" not in out, why
    # The readable part survives, so neutralizing is not the same as discarding.
    assert any(ch.isalnum() for ch in out)


def test_terminal_safe_leaves_ordinary_values_exactly_alone():
    """The whole point: the characters a real record contains must pass through untouched."""
    for value in ("color-helper@1.0.1", "/work/node_modules/color-helper/install.js",
                  "203.0.113.10", "registry.npmjs.org", "tcp:203.0.113.10:4444",
                  "npm install --no-audit --no-fund"):  # fmt: skip
        assert terminal_safe(value) == value


def test_terminal_safe_truncates_like_the_comment_escaper():
    assert len(terminal_safe("a" * 500)) == 160
    assert terminal_safe("a" * 500, 10) == "a" * 10


def test_the_diff_cli_actually_uses_the_plain_renderer():
    """Asserted through `_main`, not by reading the source: the demo runs the CLI."""
    import io
    from contextlib import redirect_stdout

    from brain.sbom import _main

    buf = io.StringIO()
    buf.reconfigure = lambda **_: None  # _main reconfigures stdout for cp1252 consoles
    with redirect_stdout(buf):
        rc = _main(["diff", str(SBOM_DIR / "color-helper_at_1.0.0.json"),
                    str(SBOM_DIR / "color-helper_at_1.0.1.json"),
                    str(SBOM_DIR / "public_key.pem")])  # fmt: skip
    out = buf.getvalue()
    assert rc == 0
    assert "color-helper@1.0.0 → color-helper@1.0.1" in out
    assert "&#" not in out
    # The claims the demo script reads out loud, verified against the real committed records.
    assert "old verified, new verified" in out
    assert "new raw IP contacted at install: 203.0.113.10" in out
    assert "partially comparable" in out
