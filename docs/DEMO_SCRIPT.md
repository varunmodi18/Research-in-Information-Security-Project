# Demo script (about 12 minutes)

This is the console demonstration from IMPLEMENTATION_PLAN.md §7.1. Each step lists what to do,
what the audience should see, and a fallback. Screenshots of the expected screens are in
[`docs/demo_assets/`](demo_assets/).

The script is also automated: `web/e2e/demo.spec.ts` performs every step and asserts the expected
result. It regenerates the screenshots each time it runs.

```
cd web && npx playwright test e2e/demo.spec.ts --repeat-each 2   # twice in a row, from a reset (§7.3 item 4)
```

## Before you start

1. Start the console with `make serve` (see `docs/OPERATIONS.md`).
2. Seed it once: `python -m maka_server seed-demo`. This creates the users `admin`, `operator` and
   `viewer`. It asks for their passwords, or reads them from `MAKA_DEMO_PASSWORDS_FILE`, one
   `username:password` line each.
3. Before each run, restore the demo state with **Admin → Reset demo…** (type `RESET`). If the
   console is stopped, `make demo-reset` does the same.
4. Check that the dashboard shows **Vineyard** (product, MAKA-E, `net`, `demo`, idle) and **Lab-Paper**
   (lab, `paper`, `toy`, seed 20260927).

| What is reset | What is kept |
|---|---|
| All networks, devices, keystores, sessions, frames, security events, readings, jobs, evaluation runs | Users and passwords, the audit log |

Onboarding Vineyard at `demo` parameters takes about 10 s on the reference laptop
(`artifacts/eval/compare_*.md`).

## 1. Product overview (1 min)

- **Do**: sign in as `operator`. Open the dashboard, then **Vineyard**.
- **Show**:
  - The green *Product network* banner.
  - The parameter label: "demo — about 60-bit security, demonstration only".
  - Three clusters of three CMs: the 12 sensor devices are *provisioned*, and the BS is *active*.
- **Say**: product networks run MAKA-E only. RP9's original mode exists only in the Lab.
- **Fallback**: `01_dashboard.png`.

## 2. Onboard (2 min)

- **Do**: on Vineyard's topology page, click **▶ Onboard**.
- **Show**:
  - Handshakes stream live, in order CH–BS, CM–BS, CM–CH.
  - Nodes turn green.
  - Then open **Security events**, filter on `HANDSHAKE_OK`: there are **21** (3 CH–BS + 9 CM–BS
    + 9 CM–CH).
- **Fallback**: `02_onboarded.png`, `02_handshake_events.png`. If onboarding is too slow on the
  presentation laptop, create a `small` network instead; the journey is the same.

## 3. Inspect a handshake (2 min)

- **Do**: click **CM-0101** → **Device details →**. Show the sessions table (CM–BS and CM–CH,
  ESTABLISHED, metadata only). Then open **Timeline** and click an **HS2** frame.
- **Show**:
  - The receiver's checks, each ticked: `sid` matches a pending HS1, `ID_R` is the intended peer, `Y`
    is a valid subgroup point, `tag_R` valid.
  - The line "Key values are never displayed".
  - Only public session identifiers are visible.
- **Fallback**: `03_device_sessions.png`, `03_timeline_checks.png`.

## 4. Secure transmission (1.5 min)

- **Do**: **Readings** → **▶ Start periodic**. After a few readings appear, click **■ Stop periodic**.
  Then open **Frames**.
- **Show**:
  - Readings appear decrypted *at the BS* (operators and admins only).
  - On the Frames page, the CM→CH `DATA_CM` payload is ciphertext, and the CH forwards a `DATA_BATCH`
    frame to the BS. The CH never holds a key for the inner payload.
- **Fallback**: `04_readings.png`, `04_frames.png`.

## 5. Lifecycle (1.5 min)

- **Do**: open **CM-0102** → **⊘ Revoke…** (type `CM-0102`). Then open **CH-01** →
  **↻ Rekey cluster**. On the topology page, click **Send readings**.
- **Show**:
  - CM-0102 turns red.
  - `REVOKE_NOTICE`/`ACK` frames appear.
  - Events show `DEVICE_REVOKED` and `KEY_ROTATED`.
  - CM-0102's next reading is rejected with `UNAUTHENTICATED_PEER`.
- **Fallback**: `05_revoked.png`, `05_lifecycle_events.png`.

## 6. Security gaps in the Lab (3 min)

- **Do**: **Lab** (red border: *not a product network*) → **L3 Insider CM impersonates its CH to another CM** →
  **Run both**.
- **Show**:
  - RP9 original: **ATTACK SUCCEEDED**. An insider CM uses the pseudo-identity scalar it knows
    (P-01).
  - MAKA-E: **ATTACK BLOCKED** with `BAD_TAG`.
  - Click **Evidence frames** to see the injected HS2 and the rejection.
- **Optional**: L5 *capture*. In RP9 every device's key falls before `k` is deleted; in MAKA-E only
  the captured device's key does.
- **Fallback**: `06_lab_L3.png`.

## 7. Failure and recovery (1 min)

- **Do**: **L2 Tamper** → **Run both**.
- **Show**: MAKA-E rejects the tampered handshake (`BAD_TAG`), and the retry succeeds.
- **Optional**: restart the server (stop and re-run `make serve`) during an onboarding. The job is shown as `aborted`, the
  devices are reset to *provisioned* (§4.8), and onboarding again succeeds.
- **Fallback**: `07_lab_L2.png`.

## 8. Evaluation (1 min)

- **Do**: open **Evaluation**.
- **Show**:
  - The limitations box first.
  - Original vs MAKA-E operation counts, bytes and timings.
  - RP9's Tables 2–6 reproduced, with the ER-02 and AM-04 annotations.
  - The OFMC results, including the negative control that *does* find an attack.
- **Say**: this is evidence, not proof (§6.7).
- **Fallback**: `08_evaluation.png`.

## If something goes wrong

| Symptom | Recovery |
|---|---|
| A job is stuck or the network shows *busy* | Cancel it from the job banner, or restart the console. A job found running at startup is marked `aborted`, and the network is rebuilt from the database (§4.8) |
| Reset demo says "Jobs running" | Wait for the job (or cancel it), then reset again |
| Login locked after failed attempts | Wait for the lock to expire (`MAKA_LOGIN_LOCK_S`), or sign in as another demo user |
| The console was restarted with a different `MAKA_KEK` | The keystores cannot be read. Run `python -m maka_server reset-demo` |
