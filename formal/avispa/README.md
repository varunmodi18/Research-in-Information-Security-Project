# Symbolic models (IMPLEMENTATION_PLAN.md M7-T1..T3)

Symbolic (Dolev–Yao) analysis under perfect-cryptography assumptions and a **bounded number of
sessions**. A clean result means "no attack within these bounds in this abstract model". It is
not a computational proof, and it says nothing about implementation bugs (§6.1, §6.7).

## Files

| File | What it is |
|---|---|
| `rp9_transcribed.hlpsl` | RP9 Figs. 4–8 **exactly as printed**, transcribed from the PDF at 220 dpi, defects included |
| `rp9_fixed.hlpsl` | The same with the **minimal** syntax fixes, each marked `FIX Dn` |
| `maka_e.hlpsl` | MAKA-E v1 AKE: initiator/responder, DH via `exp`, PSK as `psk(A,B)`, honest–honest, intruder-as-initiator, intruder-as-responder and two parallel honest sessions; goals `authentication_on n_i`, `n_r`, `secrecy_of k_ir, k_ri` |
| `maka.hlpsl` | The repository's earlier model, kept for history; its header now says it is not a faithful transcription |
| `anb/*.AnB` | The same protocols in OFMC's AnB language, which OFMC 2024 can check directly (see `NOT_RUN.md` for why) |
| `results/*.txt` | Raw OFMC outputs, written by `run_all.sh` |
| `syntax_check.py` | Structural self-check of every `.hlpsl` file (`python -m maka.cli formal --avispa`) |

## Defects in RP9's printed HLPSL (structural check + reading)

| ID | Where | Defect | Found by |
|---|---|---|---|
| D1 | Fig. 4 t2, Fig. 5 t4 | `request(...)` on the left of `=\|>` | `syntax_check.py` |
| D2 | Fig. 5 t3 | `SND(...)` used as a guard on the left of `=\|>` | `syntax_check.py` |
| D3 | Fig. 6 t2 | `request(CH,BS,em1,Nch')`: arguments reversed (the BS is the verifier) | reading |
| D4 | all roles | `Puch`, `Pucm` are locals that are never assigned or received | reading |
| D5 | Fig. 5 t4 | receives `Nch'` but requests on `Ncm'`, which is never bound | reading (found while transcribing; not in the plan's list) |
| D6 | Fig. 6 t1 | receives `{Pac}_S` with `Pac` unprimed, so never bound at the BS | reading (likewise new) |
| D7 | goal | `secrecy_of sec3` but no `secret(…, sec3, …)` fact anywhere: the goal is vacuous | `syntax_check.py` |

## Results (OFMC 2024, AnB models)

| Model | Sessions | OFMC result | Meaning |
|---|---:|---|---|
| `maka_e_ake` | 1, 2, 3 | **NO_ATTACK_FOUND** | No attack on mutual authentication (both nonces) or key secrecy within 3 sessions, with the intruder free to play either role using its own PSKs |
| `maka_e_ake_nopsk_control` | 1 | ATTACK_FOUND (weak_auth) | Negative control: the same exchange without the PSK is open to a man-in-the-middle, so the model is sensitive to the property it claims |
| `rp9_auth` | 1 | ATTACK_FOUND (weak_auth) | The intruder plays a CH or CM and forges the CH's proof |
| `rp9_auth_honest_ch` | 1 | ATTACK_FOUND (weak_auth) | With the CH and BS honest, an intruder that is a *cluster member* holds `ID_BS xor ID_CH` (RP9 gives it to every CM so it can verify the CH) and forges the CH's proof to another CM: **P-01, the insider attack** (Lab L3) |
| `rp9_auth_outsider` | 1 | NO_ATTACK_FOUND | With every role honest (outsider only), one session: agrees with RP9's published Fig. 9 ("SAFE") |
| `rp9_auth_outsider` | 2 | ATTACK_FOUND (strong_auth) | A **replay across sessions**: the same EM1 is accepted twice. RP9 says only "verify Nc" and never specifies a receiver nonce cache (S1); the runtime keeps one, which is why Lab L1 is blocked |

So RP9's published "SAFE" holds only for an outsider in a single session. As soon as an insider
or a second session is allowed, OFMC finds the attacks that the Lab demonstrates on real bytes.

Not modelled: the SOK/BDH derivation of the PSK (argued in `docs/SECURITY_ARGUMENT.md`), key
compromise (KCI is an accepted residual), and the data path.

## Reproduce

```
curl -LO http://people.compute.dtu.dk/samo/ofmc2024.zip && unzip ofmc2024.zip
OFMC=$PWD/ofmc2024/executables/linux/ofmc formal/avispa/run_all.sh
```

Tool provenance: `ofmc2024.zip` SHA-256 `e69cda4731b570da9ee5c14057a589e2a5e96fcfc9edd30669062e939cbe8c08`,
Linux binary SHA-256 `b99a4e2c1c03cff13b246a1aa3c55d020d248bc1d0ef7a66599964116196806a`.
