# Legacy full-run timings (`python -m maka.cli run`)

Commit `1d01073` · 13th Gen Intel(R) Core(TM) i7-13620H · Linux 7.0.0-34-generic · Python 3.12.3.
Fresh subprocess per run (includes interpreter start-up and imports).

| fixture | params | runs | median (s) | min (s) | max (s) |
|---|---|---:|---:|---:|---:|
| paper | demo | 3 | 2.70 | 2.70 | 2.72 |
| net | demo | 3 | 17.49 | 17.46 | 17.60 |
