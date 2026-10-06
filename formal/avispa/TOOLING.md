# Formal-analysis tooling: what was tried, what works, what is used

This file was `NOT_RUN.md` until 2026-10-06, when the AVISPA tool chain was obtained (follow-up
Part C1). Every attempt is kept below, including the ones that failed.

## Tool chain used

| Step | Tool | Build | Why this one |
|---|---|---|---|
| HLPSL → IF | `hlpsl2if` | 64-bit SPAN 1.6 package (banner "version 2.0, 06 june 2005") | The only translator obtained that accepts the `hash_func` type, which RP9's Figs. 4–8 use. Every model is also given to the original 32-bit `hlpsl2if`, and its output is recorded verbatim |
| back-end | OFMC | "Version of 2006/02/13", original 32-bit SPAN 1.6 | The OFMC that SPAN 1.6 shipped. RP9's Fig. 9 is an output of this OFMC (same banner fields: `visitedNodes`, `depth … plies`) |
| back-end | CL-AtSe | 2.2-5, original 32-bit SPAN 1.6 | The CL-AtSe that SPAN 1.6 shipped |
| back-end | CL-AtSe | 2.3-4, 64-bit SPAN 1.6 package | A second CL-AtSe build, run on every model as a cross-check |
| AnB | OFMC 2024 | standalone, BSD licence | AnB models (`anb/`); reads AnB and IF, not HLPSL |

Not used: SATMC and TA4SP (the SPAN 1.6 packages have them, but the owner asked for OFMC and
CL-AtSe), and the OFMC 2012c of the 64-bit package (see Calibration).

Default back-end options are SPAN's: typed model, sessions exactly as each HLPSL `environment`
composes them. Untyped runs (`-untyped`, `-notype`) are recorded separately for the MAKA-E models
only. Each run has a 1800 s limit; a run that hits it is recorded as `TIMEOUT`, never dropped.

## Reproduce

```
formal/avispa/fetch_avispa.sh ~/avispa_tools          # downloads, verifies SHA-256, unpacks; no root
AVISPA_TOOLS=~/avispa_tools formal/avispa/run_avispa.sh                 # every HLPSL model
AVISPA_TOOLS=~/avispa_tools formal/avispa/run_avispa.sh --calibration   # SPAN's own test suite
OFMC=/path/to/ofmc2024/executables/linux/ofmc formal/avispa/run_all.sh  # AnB models
```

`run_avispa.sh` writes raw outputs to `results/avispa/` and rebuilds `results/avispa/SUMMARY.json`
with `summarize_avispa.py`, which classifies every run from its own text (SAFE, UNSAFE, REFUSED,
ERROR, TIMEOUT, or INCOMPLETE if the file has no exit line).

Host: Ubuntu 24.04.5 LTS, kernel 7.0.0-38-generic, x86-64. No i386 multiarch, no root.

## Attempts, in order

### 2026-10-04 (M7-T1, bounded investigation)

| # | Route | Outcome |
|---|---|---|
| 1 | `https://www.avispa-project.org/` download pages and the historical `avispa-package-1.1_Linux-i686.tgz` URLs | All 404; the site no longer offers downloads |
| 2 | GitHub search for AVISPA binaries | Only users' HLPSL files and a website repository with no binaries |
| 3 | CL-AtSe at `cassis.loria.fr` / `cl-atse.loria.fr` | Hosts do not resolve or respond |
| 4 | OFMC 2024, `http://people.compute.dtu.dk/samo/ofmc2024.zip` | **Works.** Used for the AnB models |
| 5 | SPAN virtual machine | Not attempted then |

### 2026-10-06 (follow-up Part C1)

| # | Route | Outcome |
|---|---|---|
| 6 | SPAN page, `https://people.irisa.fr/Thomas.Genet/span/` (page SHA-256 `25268577…982a0e` when fetched) | Lists `span_on_ubuntu10.ova` (VirtualBox image) and, under `older.html` (SHA-256 `12642895…b272d`), the native packages `span-1.0`…`span-1.6` for Linux, macOS and Windows |
| 7 | `span-1.6-linux64-ubuntu.tar.gz` | Downloads. Its binaries need `libtinfo.so.5` and `libffi.so.6`, which Ubuntu 24.04 no longer ships. Taken from the Ubuntu archive packages `libtinfo5` and `libffi6`, unpacked with `dpkg-deb -x` into a private `compat_lib/` (never installed), and given through `LD_LIBRARY_PATH`. Then: `hlpsl2if` works and accepts `hash_func`; CL-AtSe 2.3-4 works; its OFMC (2012c) runs but fails calibration (below) |
| 8 | `span-1.6-linux.tar.gz` (the original 32-bit package) | Downloads. Its binaries are i386; the host has no i386 runtime and installing one needs root. Built a private i386 sysroot from the Ubuntu archive packages `libc6`, `libgmp10`, `libncurses5` and `libtinfo5` (i386), unpacked with `dpkg-deb -x`, and started each binary through that sysroot's loader: `ld-linux.so.2 --library-path <sysroot>/usr/lib/i386-linux-gnu <binary>`. OFMC 2006 and CL-AtSe 2.2-5 then work |
| 9 | 32-bit `hlpsl2if` through the same loader | First attempt failed with "No bytecode file specified": it is an OCaml custom-runtime executable that finds its bytecode through `argv[0]`, which is the loader here. Passing the binary twice (`ld-linux.so.2 … hlpsl2if hlpsl2if FILE`) works. It rejects the `hash_func` type (a syntax error), so RP9's printed Figs. 4–8 do not translate with it |
| 10 | The `.ova` image | Not needed once routes 7–9 worked; not downloaded |

Nothing was installed system-wide and nothing needed `sudo`.

## Downloads (all treated as untrusted; each in its own directory outside the repository)

| File | URL | SHA-256 |
|---|---|---|
| `span-1.6-linux.tar.gz` | `https://people.irisa.fr/Thomas.Genet/span/span-1.6-linux.tar.gz` | `7b0a75a6564128ac8a6c92d11a7bfb5fe328f5640f3172c0fae68e0aaec8fb20` |
| `span-1.6-linux64-ubuntu.tar.gz` | `https://people.irisa.fr/Thomas.Genet/span/span-1.6-linux64-ubuntu.tar.gz` | `6178c665898fce64e536838349caae4f7b510eeb2eb195a1dae7b2debe653211` |
| `libtinfo5_6.3-2ubuntu0.3_amd64.deb` | `http://archive.ubuntu.com/ubuntu/pool/universe/n/ncurses/` | `4df4288404108f1a156d014e8764a064e977e34e6d44931ab60451694c03c90d` |
| `libffi6_3.2.1-8_amd64.deb` | `http://archive.ubuntu.com/ubuntu/pool/main/libf/libffi/` | `fa26945b0aadfc72ec623c68be9cc59235a7fe42e2388f7015fd131f4fb06dc9` |
| `libc6_2.39-0ubuntu8.9_i386.deb` | `http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/` | `5dd733076cd5490c912c663f1e844b1d0a214301d9515708c236e6fbeb38ff8e` |
| `libgmp10_6.3.0+dfsg-3ubuntu1_i386.deb` | `http://archive.ubuntu.com/ubuntu/pool/main/g/gmp/` | `8d206aa17f5d9ca1511392dcffd8a51a103f3cbfa9c9ac56a3cf5983d3e38802` |
| `libncurses5_6.3-2ubuntu0.3_i386.deb` | `http://archive.ubuntu.com/ubuntu/pool/universe/n/ncurses/` | `3ccbc52ca31acf0e8c915ec903c361f49b5a56ad8e81364f9483a8bda91dee7f` |
| `libtinfo5_6.3-2ubuntu0.3_i386.deb` | `http://archive.ubuntu.com/ubuntu/pool/universe/n/ncurses/` | `67b85304831409ba28dcdd415af8c0e849b8d0c1ef3d6427c3c81b978d1ee176` |
| `ofmc2024.zip` | `http://people.compute.dtu.dk/samo/ofmc2024.zip` | `e69cda4731b570da9ee5c14057a589e2a5e96fcfc9edd30669062e939cbe8c08` |

`fetch_avispa.sh` re-downloads and checks the SPAN and Ubuntu files.

## Binaries run, with their checksums and banners

| Binary | SHA-256 | Banner |
|---|---|---|
| 32-bit `translator/hlpsl2if` | `b749ae6a78f2a82bfdff9d7f055df5b425e1f855aca0ff9c0476be2379076daf` | "This is hlpsl2if version 2.0. Release date : 06 june 2005." |
| 64-bit `translator/hlpsl2if` | `b9c360a2972fe24a79dc1dda271efb20caa2a00e7a8cd196e4ca00e83be0f5e6` | same banner, but accepts `hash_func` |
| 32-bit `backends/ofmc/ofmc` | `58c2e4d76654e26c86d6e9aca25a1522098bc898a96abf6af1efed136dc8c5dd` | "% OFMC % Version of 2006/02/13" (in every output) |
| 32-bit `backends/cl/cl-atse` | `25e206968892a5a5271f88d8ada8f28addabfc8a6057cc459f011c0bcc5670be` | "This is CL-AtSe, version 2.2-5" |
| 64-bit `backends/cl/cl-atse` | `3a6fa017a212a74c2d38f26b17d411bc3313107334fe2158306a551f61049f27` | "This is CL-AtSe, version 2.3-4" |
| 64-bit `backends/ofmc/ofmc` (calibration only) | `1ccaa18eb8ec08c8ae422e34ddacebd017758d112c106758f206bb063a16eb45` | "Open-Source Fixedpoint Model-Checker version 2012c" |
| OFMC 2024 `executables/linux/ofmc` | `b99a4e2c1c03cff13b246a1aa3c55d020d248bc1d0ef7a66599964116196806a` | "Open-Source Fixedpoint Model-Checker version 2024" |

## Calibration on SPAN's own test suite

The 2006-era binaries run on a 2026 host through a private loader, and the translator comes from a
different build than the back-ends. Before trusting any verdict on our models, the chains were run
on the 34 HLPSL models that SPAN 1.6 ships as its own test suite (`run_avispa.sh --calibration`;
raw table in `results/avispa/calibration_span_testsuite.txt`; default options, 120 s per run).

| Chain | Translator | Back-ends | Result |
|---|---|---|---|
| all-32 (the original SPAN 1.6) | 32-bit `hlpsl2if` 2.0 | OFMC 2006, CL-AtSe 2.2-5 | All 34 models translate. OFMC and CL-AtSe agree on 32. On the other 2 CL-AtSe gives no verdict within 120 s (`h.530`, `h.530-fix`; an error or the time limit, recorded together as `ERR/TO`) |
| **mixed (used for our models)** | 64-bit `hlpsl2if` | OFMC 2006, CL-AtSe 2.2-5 | The 64-bit translator rejects 16 of the 34 suite files: it reads a later HLPSL dialect and reports `Syn.Err(243): invalid assignment expression: missing ":="` on the old suite's `=` assignments. **On all 18 models it translates, both back-ends give exactly the all-32 verdicts** |
| all-64 | 64-bit `hlpsl2if` | OFMC 2012c (`--classic`), CL-AtSe 2.3-4 | CL-AtSe 2.3-4 agrees with CL-AtSe 2.2-5 everywhere it gives a verdict, and also answers `h.530-fix` (SAFE). **OFMC 2012c disagrees with OFMC 2006 on 6 of 18**: it reports attacks on CHAPv2, IKEv2-CHILD and PBK-fix-weak-auth, which both CL-AtSe builds and OFMC 2006 call SAFE, and calls SAFE three protocols (IKEv2-DS, ISO1, ISO3) that every other back-end attacks. Without `--classic` it hangs ("thread blocked indefinitely in an MVar operation") |

Conclusions drawn from this, and nothing more:

- The mixed chain behaves like the original SPAN 1.6 on every suite model it can read, so its
  verdicts on our models are taken as AVISPA verdicts. Whether the original 32-bit translator
  accepts each model is recorded verbatim (`results/avispa/translate/*-32.txt`); only the 64-bit
  translator's IF is run.
- OFMC 2012c is not used for any result: its verdicts on the suite are not those of the other
  back-ends, in both directions.
- CL-AtSe 2.3-4 is run on every model as a cross-check of CL-AtSe 2.2-5.

## What this tooling cannot tell

- The binaries are the published ones, checked against the SHA-256 above, but they cannot be
  rebuilt here (SPAN 1.6 ships no back-end sources), so they are trusted as distributed.
- Calibration shows agreement with the original package on its own suite. It does not show the
  tools are correct.
