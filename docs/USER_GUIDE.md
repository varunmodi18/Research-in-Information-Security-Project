# User guide

The MAKA console manages simulated IoT sensor networks that use **MAKA-E**, an enhanced version of the
RP9 (Harbi et al., 2019) authentication and key-management scheme. It also includes a separate
**Lab** for comparing MAKA-E with RP9 as published.

Everything runs in simulation, with demonstration-grade parameters. The console shows protocol
behaviour; it is not evidence of field performance or deployment-grade security (see
**Evaluation → Limitations**).

## Roles

| Role | Can |
|---|---|
| **Viewer** | Read the dashboard, topology, device sessions (metadata only), frames (ciphertext metadata), security events, timeline and evaluation results. Cannot see decrypted readings |
| **Operator** | Everything a viewer can, plus: create networks; onboard; send and schedule readings; rekey, revoke, reprovision and designate devices; see decrypted readings; run Lab scenarios and evaluations |
| **Admin** | Everything an operator can, plus: manage users, delete networks, view the audit log, reset the demo |

Buttons for actions your role cannot perform are hidden or disabled; the server enforces the same
rules.

## Networks: product and lab

| | Product network | Lab network |
|---|---|---|
| Banner | Green: *Product network* | Red border: *Attack laboratory — not a product network* |
| Protocol | MAKA-E only | MAKA-E or RP9 original |
| Randomness | Operating-system randomness | Optional seed (reproducible runs) |
| Lab scenarios and evaluations | Not allowed | Allowed |

Every network page shows its **parameter set** and what it means:

- `toy`: insecure, for hand-checkable traces.
- `demo`: about 60-bit security.
- `secure`: about 80-bit security.

All three are demonstration-only.

Topologies:

| Topology | Devices | Notes |
|---|---|---|
| `paper` | 1 BS, 1 CH, 1 CM | RP9's cost-table fixture |
| `small` | 1 BS, 1 CH, 3 CMs | |
| `net` | 1 BS, 3 CHs, 3 CMs each | |
| custom | up to 5 CHs × 8 CMs | |

## Pages

### Dashboard

All networks with their kind, mode, parameters, device counts by status, and current job. **New
network** (operator) opens the creation form: name, kind, mode (lab only), topology, parameter set and
seed (lab only). Creating a network provisions every device.

### Topology

- The network graph, with nodes coloured by device status (provisioned, authenticated, active,
  revoked, failed).
- **▶ Onboard** runs the whole MAKA-E onboarding:
  - CH–BS handshakes, then cluster membership grants;
  - CM–BS handshakes, then designation of each CM's CH;
  - CM–CH handshakes.

  The graph updates live as frames and events stream in.
- **Onboard (step mode)** goes to the Timeline instead.
- **Send readings** sends one reading from every active CM.
- Click a node for its summary, then **Device details →**.
- Links: **Frames**, **Timeline**, **Readings** (operator).

### Device

- Status history, role and cluster.
- The sessions table: peer, purpose (CM-BS, CM-CH, CH-BS), state, public session id, epoch and
  counters. No key values or key fingerprints are ever shown.
- Operator actions:

| Action | What it does |
|---|---|
| **↻ Rekey** | Runs fresh handshakes and destroys the old session keys. On a CH, it rekeys the whole cluster |
| **⊘ Revoke…** | Type the device id to confirm. The BS removes the device from its registry, the CH drops it, and its sessions and PSKs are destroyed |
| **Reprovision** | Issues a revoked device a new identity |

Revoking a **cluster head** leaves its members marked **⚠ CH revoked, awaiting re-designation**
(topology, device page and a banner). The members are not told of the revocation. They keep their
sessions with the revoked CH, and every reading they send is lost; the banner counts the lost
readings. Reprovision the CH (or designate a replacement). The new CH relays a new designation to
each member, which then drops the revoked CH's sessions and PSK.

Designating a replacement CH for a cluster is available as the `designate` job (`docs/API.md`). It
has no button in this release.

### Timeline

A step-by-step view of the frames, for teaching:

- **Step**, **Step ×10** and **Run to end** advance the scheduler.
- Click a frame to see its decoded public fields and the checks the receiver ran, each with pass or
  fail (for example `sid matches a pending HS1`, `Y is a valid subgroup point`, `tag_R valid`).
  Key values are never displayed.

### Frames

The frame log: step, sender, receiver, label, size, the receiver's verdict, and whether a frame was
injected or dropped by the Lab adversary. Payloads are shown only as ciphertext metadata. Use the
filter fields above the table to narrow the log. Lab evidence links open this page filtered to one
run.

### Readings (operator and admin)

Readings as decrypted *at the BS*, with sender, sequence number and step.

- **Send one round** sends one reading per active CM.
- **▶ Start periodic** and **■ Stop periodic** schedule readings every N steps.
- A reading from a revoked device never appears here. Look for `UNAUTHENTICATED_PEER` under Security
  events instead.

### Security events

Every protocol event, filterable by severity, type, device and network, with CSV and JSON export.
Lab evidence links open this page filtered to one run.
Typical types:

| Event | Meaning |
|---|---|
| `HANDSHAKE_OK`, `KEY_CONFIRMED` | A key exchange completed |
| `BAD_TAG` | Authentication failed: the attacker lacked the PSK, or the message was tampered with |
| `REPLAY_REJECTED` | A replayed handshake or reading |
| `UNAUTHENTICATED_PEER` | Traffic from a device that is not authorised, e.g. a revoked one |
| `DEVICE_REVOKED` | A device was revoked |
| `KEY_ROTATED` | A session was rekeyed |
| `DATA_ACCEPTED` | A reading was accepted at the BS |

### Lab (operator)

Eight attack scenarios run on fresh copies of the selected lab network: L1 replay, L2 tamper, L3
insider impersonation, L4 fake BS, L5 device capture, L6 fake member, L7 flooding and L8 revoked
device rejoining.

- **Run RP9**, **Run MAKA-E** and **Run both** show side-by-side verdicts: **ATTACK SUCCEEDED** or
  **ATTACK BLOCKED**.
- Each verdict has a one-line explanation, the names (never the values) of any secrets obtained, and
  links to the evidence frames and events.
- A verdict that differs from the prediction is flagged as a finding.

### Evaluation

- **Limitations of this evidence**: read this first.
- **Original vs enhanced comparison**:
  - The latest committed comparison (`artifacts/eval/`) or a run you start yourself (operator; pick a
    lab network, topology, parameters and seeds).
  - Charts and a **Table** view of the same numbers.
  - The §6.6 thresholds, each marked pass or fail.
- **RP9 table reproductions**: Tables 2–6 recomputed from this implementation, with the published
  numbers alongside and errata flagged (ER-02, AM-04).
- **Formal analysis**: OFMC results for MAKA-E and RP9, including the negative control. The HLPSL and
  CL-AtSe results were not obtained; the page says so.
- **Parameter security levels**.

### Admin (admin)

- Users: add, change role, enable or disable.
- The audit log of every state-changing request.
- **Reset demo…** (type `RESET`) restores the demo networks; see `docs/OPERATIONS.md`.

## Signing in and out

Sessions expire after 8 idle hours. Five failed sign-ins within 15 minutes lock the account for
15 minutes. **Sign out** is at the bottom of the sidebar.
