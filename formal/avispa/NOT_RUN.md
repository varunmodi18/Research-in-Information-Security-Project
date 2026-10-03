# What was not run, and why (IMPLEMENTATION_PLAN.md M7-T1 decision)

**Investigation (2026-10-04, bounded per M7-T1).**

| Tool | Attempt | Outcome |
|---|---|---|
| AVISPA package (`hlpsl2if`, OFMC, CL-AtSe, SATMC, TA4SP) | `https://www.avispa-project.org/` download pages and the historical `avispa-package-1.1_Linux-i686.tgz` URLs | All return 404; the site no longer offers downloads. A GitHub search finds only users' HLPSL files and a website repository with no binaries |
| SPAN virtual machine | — | Not attempted: it is distributed only as a multi-gigabyte VM image through the same defunct pages, and no hypervisor is installed on this host |
| OFMC 2024 (standalone, BSD) | `http://people.compute.dtu.dk/samo/ofmc2024.zip` | **Works.** The x86-64 Linux binary runs. It reads **AnB** and **AVISPA IF**, but not HLPSL |
| CL-AtSe | `cassis.loria.fr` / `cl-atse.loria.fr` | Hosts do not resolve or respond |

**Consequences.**

- **The HLPSL files were not run through any back-end**: translating HLPSL into IF needs `hlpsl2if`,
  which could not be obtained. `rp9_transcribed.hlpsl`, `rp9_fixed.hlpsl` and `maka_e.hlpsl` are
  committed with the structural self-check (`syntax_check.py`) only. Whether the printed RP9
  version parses under the real translator is therefore **not obtained**; the self-check reports
  the defects D1, D2 and D7.
- **OFMC was run on AnB models of the same protocols** (`anb/`). The outputs are in `results/`, and
  `README.md` explains the outcomes. These are formal results from a real tool, but on AnB
  translations written for this project, not on the HLPSL files.
- **CL-AtSe results: not obtained.** (OFMC can emit IF with `--of IF`, but there is no CL-AtSe
  binary to read it.)

The console's Evaluation page and the docs report formal results as "OFMC on AnB models:
obtained; HLPSL with OFMC/CL-AtSe: not obtained".
