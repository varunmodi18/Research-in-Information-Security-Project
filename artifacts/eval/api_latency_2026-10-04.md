# API latency with `net` loaded (V-PERF-04, demo parameters)

200 GET requests, HTTP over loopback, uvicorn, one client; 13th Gen Intel(R) Core(TM) i7-13620H, Python 3.12.3, commit `28e8fe6`.

**p95 7.99 ms** (threshold ≤ 200 ms: pass); p50 3.85 ms; max 39.62 ms.

| endpoint | n | median ms | max ms |
|---|---:|---:|---:|
| `/api/health` | 20 | 1.17 | 1.64 |
| `/api/auth/me` | 20 | 3.26 | 8.89 |
| `/api/networks` | 20 | 3.64 | 10.05 |
| `/api/networks/1` | 20 | 4.24 | 8.44 |
| `/api/networks/1/devices/CM-0101` | 20 | 3.99 | 9.21 |
| `/api/networks/1/frames?limit=200` | 20 | 6.4 | 10.54 |
| `/api/events?network_id=1&limit=200` | 20 | 4.66 | 39.62 |
| `/api/networks/1/readings` | 20 | 4.03 | 7.2 |
| `/api/lab/scenarios` | 20 | 2.97 | 5.35 |
| `/api/evaluation/runs` | 20 | 3.23 | 7.22 |
