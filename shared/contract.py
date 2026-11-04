"""Brain <-> Chamber interface. Single source of truth; change only by agreement."""

from typing import Literal

from pydantic import BaseModel, Field

MAX_EXEC_EVENTS = 500
MAX_CONNECT_EVENTS = 200
MAX_DNS_QUERIES = 200
MAX_FILE_EVENTS = 100
MAX_EXECUTED_SCRIPTS = 5
MAX_SCRIPT_CHARS = 20_000
# 2 (Nov 1): + ExecEvent.cwd, ConnectEvent.protocol, file_events, executed_scripts, decoys. Every
# addition is optional, so a v1 Chamber's results still validate.
# 3 (Nov 2): + DetonateResult.sensor (per-job witness), DetonateResult.resources (CPU/memory).
# Both optional: a v2 Chamber sends neither and the Brain keeps its v2 checks.
CONTRACT_VERSION = 3
MAX_TAIL_CHARS = 4000


class DetonateRequest(BaseModel):
    job_id: str  # uuid4, from Brain
    clone_url: str  # PR head repo clone URL (https)
    head_sha: str  # exact commit to test
    clone_token: str | None = None  # short-lived installation token; never enters container
    command: list[str] = ["npm", "install", "--no-audit", "--no-fund"]
    timeout_s: int = 180


class ExecEvent(BaseModel):
    ts: str
    pid: int
    ppid: int | None
    binary: str
    args: str
    parent_binary: str | None
    uid: int | None
    # Working directory at exec, from the kernel. For npm's lifecycle `sh -c` it is the
    # package's own directory (set by npm before any package code runs), which is how a
    # script is attributed to node_modules/<pkg>. Added Nov 1; None from older Chambers.
    cwd: str | None = None


class ConnectEvent(BaseModel):
    ts: str
    pid: int
    binary: str
    daddr: str
    dport: int
    family: str  # AF_INET / AF_INET6
    resolved_domain: str | None  # from DNS log, None = no lookup seen
    # "tcp" from Tetragon's tcp_connect; "udp"/"icmp"/… from the Chamber firewall log, which
    # rejects all non-TCP egress (those carry pid 0 and no binary). Added Nov 1.
    protocol: str = "tcp"


class FileEvent(BaseModel):
    """An open of a bait credential file planted in the sandbox (Tetragon). Added Nov 1."""

    ts: str
    pid: int
    binary: str
    path: str


class ExecutedScript(BaseModel):
    """A file an install-time process executed, copied out of the sandbox after the run.
    Untrusted content: fence it in prompts, escape it in comments."""

    path: str  # as seen in the sandbox, e.g. /work/node_modules/color-helper/install.js
    package: str | None  # node_modules/<pkg> it belongs to; None for the project's own files
    sha256: str  # of the whole file
    content: str = Field(max_length=MAX_SCRIPT_CHARS)
    truncated: bool = False


class SensorWitness(BaseModel):
    """Did Tetragon see *this* container at both ends of the install? The Chamber wraps the
    command so the container execs `/bin/true pre-<nonce>` before it and `/bin/true
    post-<nonce>` after it, with a random per-job nonce, and looks for both execs attributed
    to this container ID. Non-empty exec_events only proves the collector saw *something*.
    Code inside the sandbox can read the nonce, so this proves the collector was armed and
    attributing, not that the sandbox didn't fake an extra event. Added Nov 2."""

    pre_seen: bool
    post_seen: bool


class ResourceUsage(BaseModel):
    """Container cgroup usage, sampled while it ran (the cgroup goes away at exit). Covers
    every process in the sandbox, npm included. Added Nov 2."""

    cpu_s: float | None = None
    peak_memory_mb: float | None = None
    samples: int = 0


class DnsQuery(BaseModel):
    ts: str
    domain: str
    answers: list[str]


class DetonateResult(BaseModel):
    job_id: str
    status: Literal["completed", "timeout", "error"]
    exit_code: int | None
    duration_s: float
    exec_events: list[ExecEvent] = Field(max_length=MAX_EXEC_EVENTS)
    connect_events: list[ConnectEvent] = Field(max_length=MAX_CONNECT_EVENTS)
    dns_queries: list[DnsQuery] = Field(max_length=MAX_DNS_QUERIES)
    file_events: list[FileEvent] = Field(default_factory=list, max_length=MAX_FILE_EVENTS)
    executed_scripts: list[ExecutedScript] = Field(
        default_factory=list, max_length=MAX_EXECUTED_SCRIPTS
    )
    # This run's fake canary credentials (name -> value), so the Brain can spot them in what
    # the sandbox did. Never real secrets; redacted before anything is shown or posted.
    decoys: dict[str, str] = Field(default_factory=dict)
    stdout_tail: str = Field(max_length=MAX_TAIL_CHARS)
    stderr_tail: str = Field(max_length=MAX_TAIL_CHARS)
    truncated: bool = False  # true if events were capped
    error: str | None = None
    sensor: SensorWitness | None = None  # None from a v2 Chamber
    resources: ResourceUsage | None = None  # None from a v2 Chamber or if sampling failed
