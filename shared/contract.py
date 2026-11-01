"""Brain <-> Chamber interface. Single source of truth; change only by agreement (BUILD_PLAN §3)."""

from typing import Literal

from pydantic import BaseModel, Field

MAX_EXEC_EVENTS = 500
MAX_CONNECT_EVENTS = 200
MAX_DNS_QUERIES = 200
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


class ConnectEvent(BaseModel):
    ts: str
    pid: int
    binary: str
    daddr: str
    dport: int
    family: str  # AF_INET / AF_INET6
    resolved_domain: str | None  # from DNS log, None = no lookup seen


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
    stdout_tail: str = Field(max_length=MAX_TAIL_CHARS)
    stderr_tail: str = Field(max_length=MAX_TAIL_CHARS)
    truncated: bool = False  # true if events were capped
    error: str | None = None
