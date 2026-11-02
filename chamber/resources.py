"""Sample a container's cgroup CPU and memory while it runs (rt08: an inline CPU loop leaves no
other trace). The cgroup is removed when the container exits, so a background thread keeps the
latest reading; the last sample is at most one interval before exit.

cgroup v2 paths for Docker, by cgroup driver (to be confirmed on the Chamber, see
`CGROUP_DIRS`): systemd puts a container at system.slice/docker-<id>.scope, cgroupfs at
docker/<id>. If neither exists the result is None: no number is better than a guessed one.
"""

import threading
from pathlib import Path

from shared.contract import ResourceUsage

CGROUP_ROOT = "/sys/fs/cgroup"
CGROUP_DIRS = ("system.slice/docker-{id}.scope", "docker/{id}")
INTERVAL_S = 0.5


def parse_cpu_usage_usec(text: str) -> int | None:
    for line in text.splitlines():
        key, _, value = line.partition(" ")
        if key == "usage_usec" and value.strip().isdigit():
            return int(value)
    return None


def find_cgroup(container_id: str, root: str = CGROUP_ROOT) -> Path | None:
    for pattern in CGROUP_DIRS:
        path = Path(root) / pattern.format(id=container_id)
        if (path / "cpu.stat").is_file():
            return path
    return None


class CgroupSampler:
    def __init__(self, container_id: str, root: str = CGROUP_ROOT, interval_s: float = INTERVAL_S):
        self.container_id, self.root, self.interval_s = container_id, root, interval_s
        self._usec: int | None = None
        self._peak: int | None = None
        self._samples = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "CgroupSampler":
        self._thread.start()
        return self

    def sample_once(self) -> bool:
        """One reading; False once the cgroup is gone (or was never found)."""
        path = find_cgroup(self.container_id, self.root)
        if path is None:
            return False
        try:
            usec = parse_cpu_usage_usec((path / "cpu.stat").read_text())
            peak_file = path / "memory.peak"
            peak = int(peak_file.read_text().strip()) if peak_file.is_file() else None
        except (OSError, ValueError):
            return False
        if usec is not None:
            self._usec = max(usec, self._usec or 0)
            self._samples += 1
        if peak is not None:
            self._peak = max(peak, self._peak or 0)
        return True

    def _run(self) -> None:
        while not self._stop.is_set():
            self.sample_once()
            self._stop.wait(self.interval_s)

    def stop(self) -> ResourceUsage | None:
        self._stop.set()
        if self._thread.ident is not None:  # never started: nothing to join
            self._thread.join(timeout=2)
        if self._usec is None:
            return None
        peak_mb = round(self._peak / 2**20, 1) if self._peak is not None else None
        return ResourceUsage(cpu_s=round(self._usec / 1e6, 2), peak_memory_mb=peak_mb,
                             samples=self._samples)  # fmt: skip
