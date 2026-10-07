# Symbolic models: AVISPA (HLPSL) and OFMC 2024 (AnB)

Symbolic (Dolev–Yao) analysis assumes perfect cryptography and a **bounded number of sessions**.
"SAFE" or "no attack found" means no attack within these bounds in this abstract model. It is not a
computational proof, and it says nothing about implementation bugs.

Two separate kinds of result are kept apart everywhere in this directory, in the docs and on the
console's Evaluation page:

- **AVISPA (HLPSL)**: the HLPSL files, translated by `hlpsl2if` and checked by the AVISPA back-ends
  OFMC and CL-AtSe. This covers RP9's own model (§6.3, Figs. 4–9) and MAKA-E's key exchange.
- **OFMC 2024 (AnB)**: re-models in OFMC's AnB language, written in M7 before the AVISPA tools could
  be obtained. They can express what RP9's HLPSL cannot: the scalar multiplication behind RP9's
  authentication check (as `exp`), and a long-term key compromise after a session.

Where the tools came from, their checksums and how the chain was calibrated: `TOOLING.md`.

## Files

| File | What it is |
|---|---|
| `rp9_transcribed.hlpsl` | RP9 Figs. 4–8 **exactly as printed**, transcribed from the PDF at 220 dpi, defects included |
| `rp9_fixed.hlpsl` | The same, fixing **only what a tool rejects**: FIX D1 and FIX D8 |
| `rp9_executable.hlpsl` | Our minimally repaired version of RP9's model (fixes D1–D6, D8, D9), so that every transition can execute. Nothing in the protocol's design is changed, so its weaknesses can still show up |
| `rp9_insider.hlpsl` | Our minimally repaired version of RP9's model (fixes D1–D6, D8, D9) with the intruder as a legitimate cluster member (it holds the cluster key `S`), beside two honest members |
| `maka_e.hlpsl` | MAKA-E v1 key exchange. Four sessions: honest–honest twice in parallel, the intruder as initiator with its own PSK, the intruder as responder with its own PSK. Goals: `authentication_on n_i`, `n_r`; `secrecy_of k_ir`, `k_ri`. Diffie–Hellman via `exp` |
| `maka_e_nopsk_control.hlpsl` | Negative control: `maka_e` with the PSK removed from every tag and key. It must be attacked |
| `maka.hlpsl` | The repository's earlier model, kept for history; not a faithful transcription |
| `anb/*.AnB` | The AnB models for OFMC 2024 |
| `probes.py` | Per-transition executability probes (below) |
| `fetch_avispa.sh`, `run_avispa.sh` | Fetch the AVISPA tools (outside the repository, checksums verified); run every HLPSL model |
| `run_all.sh` | Runs every AnB model with OFMC 2024 |
| `summarize_avispa.py` | Parses the raw outputs into `results/avispa/SUMMARY.json` and `results/SUMMARY.json`, and writes the results block of this README |
| `results/avispa/` | Raw AVISPA outputs: `translate/`, `if/`, `split/`, `runs/`, `probes/`, the calibration table |
| `results/*.txt` | Raw OFMC 2024 outputs |
| `syntax_check.py` | A structural lint (not the translator; it flags D1, D2, D7) |

## Defects of RP9's printed HLPSL, and what each model fixes

| ID | Where | Defect | Rejected by a tool? | `rp9_fixed` | `rp9_executable` |
|---|---|---|---|---|---|
| D1 | Fig. 4 t2, Fig. 5 t4 | `request(...)` on the left of `=\|>` | **Yes**: CL-AtSe ("request in left-hand side."). OFMC accepts it | FIX D1 | FIX D1 |
| D2 | Fig. 5 t3 | `SND(...)` used as a guard on the left of `=\|>` | No | — | FIX D2 (an action, with a `RCV(start)` trigger) |
| D3 | Fig. 6 t2 | `request(CH,BS,em1,Nch')`: arguments reversed (the BS is the verifier) | No | — | FIX D3 |
| D4 | all roles | `Puch`, `Pucm` are locals that are never assigned or received | No | — | FIX D4 (role parameters) |
| D5 | Fig. 5 t4 | receives `Nch'` but requests on `Ncm'`, which is never bound | No | — | FIX D5 |
| D6 | Fig. 6 t1 | receives `{Pac}_S` with `Pac` unprimed, so it is never bound at the BS | No | — | FIX D6 |
| D7 | goal | `secrecy_of sec3` with no `secret(…, sec3, …)` anywhere: a vacuous goal | No | kept, reported | kept, reported |
| D8 | all roles | `F: hash_func` | **Yes**: the original translator, hlpsl2if 2.0 (`Syn.Err(10): missing or invalid type`). The later 64-bit translator accepts it | FIX D8 (`function`) | FIX D8 |
| D9 | all roles | `Pch`, `Pcm`, `A1..A4` typed `text` but holding `F(...)` values | No, but in AVISPA's default typed model a `text` variable never matches an `F(...)` value, so the CH's step 2 can never fire | — | FIX D9 (`message`) |

D1–D7 were found in M7 by reading and by `syntax_check.py`. D8 and D9 were found by running the tools.

## Comparison with RP9's Fig. 9

RP9 prints one OFMC result (Fig. 9): **SAFE, 1501 visited nodes, depth 7 plies**.

- `rp9_transcribed` with OFMC (version of 2006/02/13) gives **exactly that**: SAFE, 1501 nodes,
  depth 7. The same holds for every goal checked alone. So Fig. 9 is reproducible from the printed
  model, with the 64-bit translator (the original one rejects `hash_func`, D8).
- CL-AtSe refuses the printed model (D1). Fig. 9 shows only OFMC.
- **The SAFE is vacuous** (register OB-11). The executability probes show that only the first
  transition of each role can ever fire (CM t1, CH t1, BS t1 of 8): the CH's step 2 never matches
  (D9), and everything after it depends on it. No `request` and no `secret` of the authentication
  phase is ever reached, so every goal holds trivially. `rp9_fixed` is the same: OFMC SAFE 1501/7,
  and CL-AtSe SAFE after analysing 0–1 states.
- In our minimally repaired version of RP9's model (fixes D1–D6, D8, D9; `rp9_executable`, all 8
  transitions reachable), OFMC reports **attacks on all three authentication goals** `em1`, `em2`,
  `em3`. CL-AtSe reports attacks on `em1` and `em2`, and crashes on `em3` (`Atom number unknown`);
  the crash is recorded as ERROR.
  - The attack is simple: the intruder builds `{A1.A2.Nch}_Pucm` from values of its choice, and the
    member accepts it.
  - This UNSAFE is a verdict on our minimally repaired version of RP9's model, not on RP9's model
    as printed (which cannot run) and not by itself evidence of P-01. RP9 models the scalar
    multiplication as an opaque `F(r.G)`, so the check its authentication rests on,
    `A2 = (ID_BS ⊕ ID_CH)·A1`, is in neither model (register OB-12).

## What each result shows, and what it does not

- **RP9, AVISPA.**
  - *Shows*: Fig. 9's numbers are what OFMC prints for the printed model. That model's
    authentication phase never runs, so Fig. 9 verifies nothing about it.
  - *Shows*: our minimally repaired version of RP9's model (fixes D1–D6, D8, D9) is UNSAFE: it
    does not authenticate, because the check it would need is not expressible in it.
  - *Does not show*: whether RP9's real protocol (with the scalar-multiplication check) is secure or
    broken; the HLPSL cannot say.
- **RP9, insider (`rp9_insider`).** In our minimally repaired version of RP9's model (fixes D1–D6,
  D8, D9), the intruder is a legitimate CM holding the cluster key `S` and its own key pair.
  - *Shows*: such an insider learns `sec1` (OFMC and CL-AtSe), which is sent under `S`. For `sec2`
    and `sec3` CL-AtSe finds no attack and OFMC times out (30 min).
  - *Shows*: it defeats the authentication goals `em1`, `em2` (both back-ends) and `em3`
    (CL-AtSe; OFMC times out), as an outsider does in `rp9_executable`.
  - In `rp9_executable` (the same repaired model, outsiders only), CL-AtSe finds no secrecy attack on `sec1`–`sec3`, and OFMC times out on
    them. Without the cluster key `S`, the outsider does not learn the secrets.
  - *Does not show*: the specific insider forgery P-01 (forging `A2` from `ID_BS ⊕ ID_CH`), for the
    same reason as above. P-01 is shown by OFMC 2024 on `anb/rp9_auth_honest_ch.AnB`, which models
    the scalar multiplication, and on real bytes by Lab L3.
- **RP9, AnB (OFMC 2024).**
  - *Shows*: with the scalar multiplication modelled, an insider CM impersonates the CH to another
    member (P-01, 1 session).
  - *Shows*: with outsiders only, 1 session shows no attack. At 2 sessions, without a receiver-side
    nonce record, replay succeeds. RP9's replay protection rests entirely on that record, which RP9
    does not specify. The runtime keeps one, which is why Lab L1 is blocked.
- **MAKA-E, AVISPA (typed, AVISPA's default).**
  - *Shows*: OFMC and both CL-AtSe builds find no attack on authentication of either nonce or
    secrecy of either key, in 4 sessions with the intruder playing either role with its own PSKs.
    This holds for all goals together and for each goal alone.
  - *Shows*: every transition of both roles can execute, so these results are not vacuous.
  - *Shows*: the no-PSK control is attacked by every back-end, so the model detects the attacks it
    claims to exclude.
  - *Does not show*: anything beyond these 4 sessions, about the SOK-derived PSK (modelled as a
    constant), or about the membership, revocation and data layers (not modelled).
- **MAKA-E, AVISPA untyped.** OFMC (untyped) finds no attack. **CL-AtSe (untyped) reports an attack
  on `n_r`.** This is recorded as a finding, not hidden.
  - It is a field-boundary ambiguity of the symbolic model: the intruder appends `Sid.R.I.X` to `X`
    in HS1, and the initiator then parses `N_R` as `X.Sid.R.I.N_R`. Both sides agree on the
    flattened transcript but disagree on `n_r`.
  - The implementation excludes it: every field is length-prefixed, and `N_R` and `X` have fixed
    widths. Both shifted messages are rejected, `BAD_POINT` for HS1 and `DECODE_ERROR` for HS2
    (`tests/enhanced/test_ake.py::test_untyped_boundary_shift_*`).
  - This depends on the encoding, which the HLPSL model does not capture.
- **MAKA-E forward secrecy, AnB (OFMC 2024).** The PSK is published after the session; the goal is
  secrecy of that session's keys.
  - **Result: no attack at 1 session; the 2-session trace is impersonation after long-term key compromise, which the AnB language cannot exclude, so forward secrecy is not established symbolically beyond 1 session.**
  - Detail of the 2-session trace: the keys that leak belong to a responder session that the
    intruder itself opened (with `X = g`) and completed after the PSK had leaked from the other
    session. The result is recorded as OFMC reported it; the model is unchanged.
  - The no-DH control is attacked at 1 and 2 sessions: there the keys of a completed honest session
    do leak.

## Executability probes

A SAFE verdict means little if a transition can never fire. `probes.py` gives each transition of
each role an extra fresh marker, sent in clear and declared `secret`. A secrecy attack on a
transition's marker proves it can execute; SAFE proves it never executes. The instrumentation only
adds intruder knowledge, so a "never executes" carries over to the uninstrumented model.

## Results

The tables below are generated from the raw outputs by `summarize_avispa.py`. A test
(`tests/test_formal.py`) checks that they equal what the committed outputs parse to.

<!-- BEGIN GENERATED RESULTS (summarize_avispa.py) -->
### AVISPA (HLPSL): translation

| Model | hlpsl2if (64-bit SPAN 1.6) | hlpsl2if 2.0 (original 32-bit SPAN 1.6) |
|---|---|---|
| `rp9_transcribed` | accepted | **rejected**: `Syntax error: Line 26, Col 19 (offset 1367-1375, string "hash_func")`; `Syn.Err(10): missing or invalid type in variables declaration` |
| `rp9_fixed` | accepted | accepted: `HLPSL spec: warning(7): unknown type of constant xor in transition 1 of role basestation` |
| `rp9_executable` | accepted | accepted: `HLPSL spec: warning(7): unknown type of constant xor in transition 1 of role basestation` |
| `rp9_insider` | accepted | accepted: `HLPSL spec: warning(7): unknown type of constant xor in transition 1 of role basestation` |
| `maka_e` | accepted | **rejected**: `Syntax error: Line 31, Col 61 (offset 2287-2295, string "hash_func")`; `Syn.Err(10): missing or invalid type in variables declaration` |
| `maka_e_nopsk_control` | accepted | **rejected**: `Syntax error: Line 6, Col 61 (offset 466-474, string "hash_func")`; `Syn.Err(10): missing or invalid type in variables declaration` |

### AVISPA (HLPSL): OFMC, CL-AtSe, all goals together

| Model | Sessions | Back-end | Verdict | Statistics | Raw output |
|---|---|---|---|---|---|
| `rp9_transcribed` | 3 as printed in Fig. 8: (cm,ch,bs), (i,ch,bs), (cm,i,bs) | OFMC (2006/02/13) | **SAFE** | 1501 nodes, depth 7, 1.36s | `results/avispa/runs/rp9_transcribed.ofmc2006.txt` |
| `rp9_transcribed` | 3 as printed in Fig. 8: (cm,ch,bs), (i,ch,bs), (cm,i,bs) | CL-AtSe 2.2-5 | **REFUSED**: `request in left-hand side.` | — | `results/avispa/runs/rp9_transcribed.clatse225.txt` |
| `rp9_transcribed` | 3 as printed in Fig. 8: (cm,ch,bs), (i,ch,bs), (cm,i,bs) | CL-AtSe 2.3-4 | **REFUSED**: `request in left-hand side.` | — | `results/avispa/runs/rp9_transcribed.clatse234.txt` |
| `rp9_fixed` | 3 as printed in Fig. 8: (cm,ch,bs), (i,ch,bs), (cm,i,bs) | OFMC (2006/02/13) | **SAFE** | 1501 nodes, depth 7, 1.21s | `results/avispa/runs/rp9_fixed.ofmc2006.txt` |
| `rp9_fixed` | 3 as printed in Fig. 8: (cm,ch,bs), (i,ch,bs), (cm,i,bs) | CL-AtSe 2.2-5 | **SAFE** | 1 analysed, 0 reachable | `results/avispa/runs/rp9_fixed.clatse225.txt` |
| `rp9_fixed` | 3 as printed in Fig. 8: (cm,ch,bs), (i,ch,bs), (cm,i,bs) | CL-AtSe 2.3-4 | **SAFE** | 1 analysed, 0 reachable | `results/avispa/runs/rp9_fixed.clatse234.txt` |
| `rp9_executable` | 3 as printed in Fig. 8: (cm,ch,bs), (i,ch,bs), (cm,i,bs) | OFMC (2006/02/13) | **UNSAFE**: `authentication_on_em2` | 3 nodes, depth 2, 0.01s | `results/avispa/runs/rp9_executable.ofmc2006.txt` |
| `rp9_executable` | 3 as printed in Fig. 8: (cm,ch,bs), (i,ch,bs), (cm,i,bs) | CL-AtSe 2.2-5 | **UNSAFE**: `Authentication attack on (cm,ch,em2,Nch(2))` | 345 analysed, 87 reachable | `results/avispa/runs/rp9_executable.clatse225.txt` |
| `rp9_executable` | 3 as printed in Fig. 8: (cm,ch,bs), (i,ch,bs), (cm,i,bs) | CL-AtSe 2.3-4 | **UNSAFE**: `Authentication attack on (cm,ch,em2,Nch(2))` | 345 analysed, 87 reachable | `results/avispa/runs/rp9_executable.clatse234.txt` |
| `rp9_insider` | 3: (cm,ch,bs), (cm2,ch,bs), (i,ch,bs) with i a legitimate CM holding S | OFMC (2006/02/13) | **UNSAFE**: `secrecy_of_sec1` | 0 nodes, depth 0, 0.00s | `results/avispa/runs/rp9_insider.ofmc2006.txt` |
| `rp9_insider` | 3: (cm,ch,bs), (cm2,ch,bs), (i,ch,bs) with i a legitimate CM holding S | CL-AtSe 2.2-5 | **UNSAFE**: `Secrecy attack on (dummy_nonce)` | 0 analysed, 0 reachable | `results/avispa/runs/rp9_insider.clatse225.txt` |
| `rp9_insider` | 3: (cm,ch,bs), (cm2,ch,bs), (i,ch,bs) with i a legitimate CM holding S | CL-AtSe 2.3-4 | **UNSAFE**: `Secrecy attack on (dummy_nonce)` | 0 analysed, 0 reachable | `results/avispa/runs/rp9_insider.clatse234.txt` |
| `maka_e` | 4: (a,b) x2 honest, (i,b) with i's own PSK, (a,i) with i's own PSK | OFMC (2006/02/13) | **SAFE** | 3268 nodes, depth 12, 3.89s | `results/avispa/runs/maka_e.ofmc2006.txt` |
| `maka_e` | 4: (a,b) x2 honest, (i,b) with i's own PSK, (a,i) with i's own PSK | OFMC (2006/02/13), untyped | **SAFE** | 3918 nodes, depth 12, 4.11s | `results/avispa/runs/maka_e.ofmc2006-untyped.txt` |
| `maka_e` | 4: (a,b) x2 honest, (i,b) with i's own PSK, (a,i) with i's own PSK | CL-AtSe 2.2-5 | **SAFE** | 7885 analysed, 4809 reachable | `results/avispa/runs/maka_e.clatse225.txt` |
| `maka_e` | 4: (a,b) x2 honest, (i,b) with i's own PSK, (a,i) with i's own PSK | CL-AtSe 2.2-5, untyped | **UNSAFE**: `Authentication attack on (b.a.n_r.exp(g,n1(X)).n1(Sid).b.a.n13(Nr))` | 16 analysed, 14 reachable | `results/avispa/runs/maka_e.clatse225-untyped.txt` |
| `maka_e` | 4: (a,b) x2 honest, (i,b) with i's own PSK, (a,i) with i's own PSK | CL-AtSe 2.3-4 | **SAFE** | 7885 analysed, 4809 reachable | `results/avispa/runs/maka_e.clatse234.txt` |
| `maka_e_nopsk_control` | 4: (a,b) x2 honest, (i,b), (a,i); no PSK in the tags | OFMC (2006/02/13) | **UNSAFE**: `authentication_on_n_r` | 1 nodes, depth 1, 0.01s | `results/avispa/runs/maka_e_nopsk_control.ofmc2006.txt` |
| `maka_e_nopsk_control` | 4: (a,b) x2 honest, (i,b), (a,i); no PSK in the tags | OFMC (2006/02/13), untyped | **UNSAFE**: `authentication_on_n_r` | 1 nodes, depth 1, 0.00s | `results/avispa/runs/maka_e_nopsk_control.ofmc2006-untyped.txt` |
| `maka_e_nopsk_control` | 4: (a,b) x2 honest, (i,b), (a,i); no PSK in the tags | CL-AtSe 2.2-5 | **UNSAFE**: `Secrecy attack on ({kir.exp(g,n1(X)).{n1(Sid).a.b.cm_ch.n1(Ni).exp(g,n1(X)).n1(Sid).b.a.Nr(2).g}_h.cm_ch}_h)` | 9 analysed, 9 reachable | `results/avispa/runs/maka_e_nopsk_control.clatse225.txt` |
| `maka_e_nopsk_control` | 4: (a,b) x2 honest, (i,b), (a,i); no PSK in the tags | CL-AtSe 2.2-5, untyped | **UNSAFE**: `Secrecy attack on ({kir.exp(g,n1(X)).{n1(Sid).a.b.cm_ch.n1(Ni).exp(g,n1(X)).n1(Sid).b.a.Nr(2).g}_h.cm_ch}_h)` | 11 analysed, 11 reachable | `results/avispa/runs/maka_e_nopsk_control.clatse225-untyped.txt` |
| `maka_e_nopsk_control` | 4: (a,b) x2 honest, (i,b), (a,i); no PSK in the tags | CL-AtSe 2.3-4 | **UNSAFE**: `Secrecy attack on ({kir.exp(g,n1(X)).{n1(Sid).a.b.cm_ch.n1(Ni).exp(g,n1(X)).n1(Sid).b.a.Nr(2).g}_h.cm_ch}_h)` | 9 analysed, 9 reachable | `results/avispa/runs/maka_e_nopsk_control.clatse234.txt` |

### AVISPA (HLPSL): one goal at a time (`hlpsl2if --split`)

| Model | Goal | OFMC (2006/02/13) | CL-AtSe 2.2-5 |
|---|---|---|---|
| `rp9_transcribed` | `auth-em1` | SAFE (1501 nodes, depth 7, 0.94s) | REFUSED |
| `rp9_transcribed` | `auth-em2` | SAFE (1501 nodes, depth 7, 0.94s) | REFUSED |
| `rp9_transcribed` | `auth-em3` | SAFE (1501 nodes, depth 7, 0.93s) | REFUSED |
| `rp9_transcribed` | `secrecy-sec1` | SAFE (1501 nodes, depth 7, 0.99s) | REFUSED |
| `rp9_transcribed` | `secrecy-sec2` | SAFE (1501 nodes, depth 7, 1.01s) | REFUSED |
| `rp9_transcribed` | `secrecy-sec3` | SAFE (1501 nodes, depth 7, 1.39s) | REFUSED |
| `rp9_fixed` | `auth-em1` | SAFE (1501 nodes, depth 7, 0.94s) | SAFE (0 analysed, 0 reachable) |
| `rp9_fixed` | `auth-em2` | SAFE (1501 nodes, depth 7, 1.42s) | SAFE (0 analysed, 0 reachable) |
| `rp9_fixed` | `auth-em3` | SAFE (1501 nodes, depth 7, 1.02s) | SAFE (0 analysed, 0 reachable) |
| `rp9_fixed` | `secrecy-sec1` | SAFE (1501 nodes, depth 7, 0.97s) | SAFE (0 analysed, 0 reachable) |
| `rp9_fixed` | `secrecy-sec2` | SAFE (1501 nodes, depth 7, 1.00s) | SAFE (0 analysed, 0 reachable) |
| `rp9_fixed` | `secrecy-sec3` | SAFE (1501 nodes, depth 7, 0.94s) | SAFE (0 analysed, 0 reachable) |
| `rp9_executable` | `auth-em1` | UNSAFE (6 nodes, depth 2, 0.03s) | UNSAFE (372 analysed, 92 reachable) |
| `rp9_executable` | `auth-em2` | UNSAFE (3 nodes, depth 2, 0.01s) | UNSAFE (345 analysed, 87 reachable) |
| `rp9_executable` | `auth-em3` | UNSAFE (553 nodes, depth 4, 1.04s) | ERROR |
| `rp9_executable` | `secrecy-sec1` | TIMEOUT | SAFE (1037 analysed, 103 reachable) |
| `rp9_executable` | `secrecy-sec2` | TIMEOUT | SAFE (1037 analysed, 103 reachable) |
| `rp9_executable` | `secrecy-sec3` | TIMEOUT | SAFE (1037 analysed, 103 reachable) |
| `rp9_insider` | `auth-em1` | UNSAFE (6 nodes, depth 1, 0.03s) | UNSAFE (2 analysed, 2 reachable) |
| `rp9_insider` | `auth-em2` | UNSAFE (1 nodes, depth 1, 0.01s) | UNSAFE (0 analysed, 0 reachable) |
| `rp9_insider` | `auth-em3` | TIMEOUT | UNSAFE (12 analysed, 12 reachable) |
| `rp9_insider` | `secrecy-sec1` | UNSAFE (0 nodes, depth 0, 0.00s) | UNSAFE (0 analysed, 0 reachable) |
| `rp9_insider` | `secrecy-sec2` | TIMEOUT | SAFE (1 analysed, 1 reachable) |
| `rp9_insider` | `secrecy-sec3` | TIMEOUT | SAFE (1 analysed, 1 reachable) |
| `maka_e` | `auth-n_i` | SAFE (3268 nodes, depth 12, 2.30s) | SAFE (7885 analysed, 4809 reachable) |
| `maka_e` | `auth-n_r` | SAFE (3268 nodes, depth 12, 2.43s) | SAFE (139 analysed, 119 reachable) |
| `maka_e` | `secrecy-k_ir` | SAFE (3268 nodes, depth 12, 2.63s) | SAFE (893 analysed, 715 reachable) |
| `maka_e` | `secrecy-k_ri` | SAFE (3268 nodes, depth 12, 2.60s) | SAFE (893 analysed, 715 reachable) |
| `maka_e_nopsk_control` | `auth-n_i` | UNSAFE (4 nodes, depth 1, 0.00s) | UNSAFE (13 analysed, 13 reachable) |
| `maka_e_nopsk_control` | `auth-n_r` | UNSAFE (1 nodes, depth 1, 0.00s) | UNSAFE (0 analysed, 0 reachable) |
| `maka_e_nopsk_control` | `secrecy-k_ir` | UNSAFE (1 nodes, depth 1, 0.00s) | UNSAFE (0 analysed, 0 reachable) |
| `maka_e_nopsk_control` | `secrecy-k_ri` | UNSAFE (1 nodes, depth 1, 0.00s) | UNSAFE (0 analysed, 0 reachable) |

### Executability probes (OFMC 2006): which transitions can ever fire

| Model | Can execute | Never execute |
|---|---|---|
| `rp9_transcribed` | bs1, ch1, cm1 (3/8) | bs2, ch2, ch3, ch4, cm2 |
| `rp9_fixed` | bs1, ch1, cm1 (3/8) | bs2, ch2, ch3, ch4, cm2 |
| `rp9_executable` | bs1, bs2, ch1, ch2, ch3, ch4, cm1, cm2 (8/8) | — |
| `rp9_insider` | bs1, bs2, ch1, ch2, ch3, cm1, cm2 (7/8) | ch4 (TIMEOUT) |
| `maka_e` | i1, i2, r1, r2 (4/4) | — |
| `maka_e_nopsk_control` | i1, i2, r1, r2 (4/4) | — |

### OFMC 2024 (AnB models)

| Model | Sessions | Verdict | Goal violated | Statistics (as printed) | Raw output |
|---|---:|---|---|---|---|
| `maka_e_ake` | 1 | **NO_ATTACK_FOUND** | — | 11 nodes, depth 5, 247 ms | `results/maka_e_ake.sessions1.txt` |
| `maka_e_ake` | 2 | **NO_ATTACK_FOUND** | — | 439 nodes, depth 9, 781 ms | `results/maka_e_ake.sessions2.txt` |
| `maka_e_ake` | 3 | **NO_ATTACK_FOUND** | — | 149833 ms | `results/maka_e_ake.sessions3.txt` |
| `maka_e_ake_fs` | 1 | **NO_ATTACK_FOUND** | — | 15 nodes, depth 6, 388 ms | `results/maka_e_ake_fs.sessions1.txt` |
| `maka_e_ake_fs` | 2 | **ATTACK_FOUND** | `secrets` | 356 nodes, depth 6, 914 ms | `results/maka_e_ake_fs.sessions2.txt` |
| `maka_e_ake_fs_nodh_control` | 1 | **ATTACK_FOUND** | `secrets` | 10 nodes, depth 4, 79 ms | `results/maka_e_ake_fs_nodh_control.sessions1.txt` |
| `maka_e_ake_fs_nodh_control` | 2 | **ATTACK_FOUND** | `secrets` | 54 nodes, depth 4, 119 ms | `results/maka_e_ake_fs_nodh_control.sessions2.txt` |
| `maka_e_ake_nopsk_control` | 1 | **ATTACK_FOUND** | `weak_auth` | 3 nodes, depth 2, 207 ms | `results/maka_e_ake_nopsk_control.sessions1.txt` |
| `rp9_auth` | 1 | **ATTACK_FOUND** | `weak_auth` | 1 nodes, depth 1, 105 ms | `results/rp9_auth.sessions1.txt` |
| `rp9_auth_honest_ch` | 1 | **ATTACK_FOUND** | `weak_auth` | 1 nodes, depth 1, 106 ms | `results/rp9_auth_honest_ch.sessions1.txt` |
| `rp9_auth_outsider` | 1 | **NO_ATTACK_FOUND** | — | 5 nodes, depth 5, 98 ms | `results/rp9_auth_outsider.sessions1.txt` |
| `rp9_auth_outsider` | 2 | **ATTACK_FOUND** | `strong_auth` | 8 nodes, depth 3, 110 ms | `results/rp9_auth_outsider.sessions2.txt` |
<!-- END GENERATED RESULTS -->

## Reproduce

```
formal/avispa/fetch_avispa.sh ~/avispa_tools
AVISPA_TOOLS=~/avispa_tools formal/avispa/run_avispa.sh                # HLPSL models, 30 min limit per run
AVISPA_TOOLS=~/avispa_tools formal/avispa/run_avispa.sh --calibration  # SPAN's own test suite
OFMC=/path/to/ofmc2024/executables/linux/ofmc formal/avispa/run_all.sh # AnB models (ofmc2024.zip, TOOLING.md)
```
