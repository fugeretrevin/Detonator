"""Brain <-> Chamber interface. Single source of truth; change only by agreement (BUILD_PLAN §3)."""

from typing import Literal

from pydantic import BaseModel, Field

MAX_EXEC_EVENTS = 500
MAX_CONNECT_EVENTS = 200
MAX_DNS_QUERIES = 200
MAX_FILE_EVENTS = 100
MAX_EXECUTED_SCRIPTS = 5
MAX_SCRIPT_CHARS = 20_000
# 2 (Nov 1): + ExecEvent.cwd, ConnectEvent.protocol, file_events, executed_scripts. Every
# addition is optional, so a v1 Chamber's results still validate.
CONTRACT_VERSION = 2
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
    stdout_tail: str = Field(max_length=MAX_TAIL_CHARS)
    stderr_tail: str = Field(max_length=MAX_TAIL_CHARS)
    truncated: bool = False  # true if events were capped
    error: str | None = None
