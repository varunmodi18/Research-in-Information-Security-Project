"""Shared timing helper: warm-up runs, then median and IQR of `perf_counter` samples."""

from __future__ import annotations

import platform
import statistics
import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

WARMUP = 3


@dataclass(frozen=True)
class Timing:
    name: str
    params: str
    iterations: int
    warmup: int
    median_ms: float
    q1_ms: float
    q3_ms: float

    @property
    def iqr_ms(self) -> float:
        return self.q3_ms - self.q1_ms

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "iqr_ms": self.iqr_ms}


def measure(name: str, params: str, fn: Callable[[int], object], iterations: int,
            warmup: int = WARMUP) -> Timing:
    """Calls fn(i) `warmup` times untimed, then `iterations` times timed. `i` lets callers vary
    inputs per call (e.g. a fresh identity per hash-to-point) so caching cannot flatter a result."""
    for i in range(warmup):
        fn(-1 - i)
    samples = []
    for i in range(iterations):
        start = time.perf_counter()
        fn(i)
        samples.append((time.perf_counter() - start) * 1000.0)
    if len(samples) >= 2:
        q1, _, q3 = statistics.quantiles(samples, n=4, method="inclusive")
    else:
        q1 = q3 = samples[0]
    return Timing(name, params, iterations, warmup, statistics.median(samples), q1, q3)


def machine() -> dict[str, str]:
    cpu = platform.processor() or platform.machine()
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                                text=True, check=False).stdout.strip()
    except OSError:
        commit = "unknown"
    return {"cpu": cpu, "os": f"{platform.system()} {platform.release()}",
            "python": platform.python_version(), "commit": commit or "unknown"}
