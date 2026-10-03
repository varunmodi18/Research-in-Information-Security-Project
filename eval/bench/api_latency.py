"""API latency with `net` loaded (V-PERF-04, NFR-PERF-02).

    python -m eval.bench.api_latency [--params demo] [--requests 200] [--out artifacts/eval/api_latency]

Starts the console on a throwaway SQLite database (uvicorn on 127.0.0.1, a real HTTP socket), creates
and onboards an enhanced `net` product network, sends readings so the frame, event and reading logs are
populated, then times `--requests` GETs spread round-robin over the non-cryptographic read endpoints.
The threshold is p95 <= 200 ms. Endpoints that start protocol work (jobs) are excluded by definition.
"""

from __future__ import annotations

import argparse
import json
import socket
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import uvicorn

from eval.bench.timing import machine
from maka_server.main import create_app
from maka_server.services.users import create_user
from maka_server.settings import Settings

THRESHOLD_MS = 200.0
PASSWORD = "latency-bench-password"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait(c: httpx.Client, job_id: int, timeout: float = 600.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body: dict[str, Any] = c.get(f"/api/jobs/{job_id}").json()
        if body["state"] in ("succeeded", "failed", "cancelled", "aborted"):
            if body["state"] != "succeeded":
                raise RuntimeError(f"job {job_id}: {body['state']} {body.get('error')}")
            return body
        time.sleep(0.2)
    raise TimeoutError(job_id)


def measure(params: str, n_requests: int) -> dict[str, Any]:
    tmp = Path(tempfile.mkdtemp(prefix="maka-latency-"))
    settings = Settings(env="test", db_url=f"sqlite:///{tmp / 'maka.db'}", static_dir=tmp / "no-ui",
                        params_default=params)
    app = create_app(settings)
    create_user(app.state.ctx, "bench", PASSWORD, "operator")
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=60) as c:
            csrf = c.post("/api/auth/login", json={"username": "bench", "password": PASSWORD}).json()["csrf_token"]
            c.headers["X-CSRF-Token"] = csrf
            net = c.post("/api/networks", json={"name": "latency-net", "kind": "product", "mode": "enhanced",
                                                "params": params, "template": "net"}).json()
            nid = net["id"]

            def job(kind: str, args: dict[str, Any]) -> dict[str, Any]:
                r = c.post(f"/api/networks/{nid}/jobs",
                           json={"type": kind, "args": args, "idempotency_key": f"{kind}-{time.monotonic_ns()}"})
                r.raise_for_status()
                return _wait(c, r.json()["job_id"])

            t0 = time.perf_counter()
            job("onboard", {})
            onboard_s = time.perf_counter() - t0
            job("send_readings", {"count": 2})
            detail = c.get(f"/api/networks/{nid}").json()
            device = next(d["ident"] for d in detail["devices"] if d["role"] == "CM")
            endpoints = ["/api/health", "/api/auth/me", "/api/networks", f"/api/networks/{nid}",
                         f"/api/networks/{nid}/devices/{device}", f"/api/networks/{nid}/frames?limit=200",
                         f"/api/events?network_id={nid}&limit=200", f"/api/networks/{nid}/readings",
                         "/api/lab/scenarios", "/api/evaluation/runs"]
            for path in endpoints:  # warm-up, and fail loudly on a wrong path
                c.get(path).raise_for_status()
            samples: dict[str, list[float]] = {p: [] for p in endpoints}
            for i in range(n_requests):
                path = endpoints[i % len(endpoints)]
                t = time.perf_counter()
                c.get(path).raise_for_status()
                samples[path].append((time.perf_counter() - t) * 1000)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
    every = sorted(x for v in samples.values() for x in v)
    p95 = statistics.quantiles(every, n=100, method="inclusive")[94]
    return {
        "meta": {**machine(), "params": params, "requests": n_requests, "network": "net (enhanced, product)",
                 "transport": "HTTP over loopback, uvicorn, one client", "onboard_s": round(onboard_s, 2)},
        "p50_ms": round(statistics.median(every), 2), "p95_ms": round(p95, 2), "max_ms": round(every[-1], 2),
        "threshold_ms": THRESHOLD_MS, "pass": p95 <= THRESHOLD_MS,
        "per_endpoint": {p: {"n": len(v), "median_ms": round(statistics.median(v), 2), "max_ms": round(max(v), 2)}
                         for p, v in samples.items()},
    }


def to_markdown(doc: dict[str, Any]) -> str:
    m = doc["meta"]
    lines = [f"# API latency with `net` loaded (V-PERF-04, {m['params']} parameters)", "",
             f"{m['requests']} GET requests, {m['transport']}; {m['cpu']}, Python {m['python']}, commit `{m['commit']}`.",
             "", (f"**p95 {doc['p95_ms']} ms** (threshold ≤ {doc['threshold_ms']:.0f} ms: "
                  f"{'pass' if doc['pass'] else 'FAIL'}); p50 {doc['p50_ms']} ms; max {doc['max_ms']} ms."), "",
             "| endpoint | n | median ms | max ms |", "|---|---:|---:|---:|"]
    for p, v in doc["per_endpoint"].items():
        lines.append(f"| `{p}` | {v['n']} | {v['median_ms']} | {v['max_ms']} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--params", default="demo", choices=["toy", "demo", "secure"])
    ap.add_argument("--requests", type=int, default=200)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    doc = measure(args.params, args.requests)
    md = to_markdown(doc)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.with_suffix(".json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        out.with_suffix(".md").write_text(md, encoding="utf-8")
    sys.stdout.write(md)
    return 0 if doc["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
