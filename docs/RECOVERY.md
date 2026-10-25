# Cluster-head replacement (operator-approved, with a ranked recommendation)

**Tested, not statistically evaluated.** This layer is not part of RP9, and not part of MAKA-E's
security argument (register IA-20, IA-21; errata E-14).

## Purpose

A cluster head relays and batches its members' readings. It can drop them without being able to
read or forge them (`docs/RESIDUAL_RISKS.md` R-12). Cryptography does not detect this: the CH holds
valid keys.

The experimental behaviour monitor (`docs/BEHAVIOUR.md`) can flag a CH whose behaviour is abnormal.
This layer turns such a flag into an operator workflow:

1. a **"CH suspected" alert**;
2. a **ranked recommendation** of which member should take over;
3. an **operator-confirmed promotion** of that member to cluster head.

## Design

### Promotion without new keys (`EnhancedBS.promote`, `EnhancedNetwork.promote`)

In MAKA-E, keys are bound to identities: `Pr_i = k·H(ID_i)`, and pairwise PSKs are derived from
it. Being a cluster head is an authorisation in the BS registry, not a key. So a member can become
its cluster's CH without any new key:

1. **At the BS** (`promote(cluster, member)`):
   - It checks that `member` is a registered, non-revoked CM of `cluster` with a current CM–BS
     session. Anything else is refused with `UNAUTHORISED_PEER`, and nothing changes.
   - It revokes the cluster's current CH by the existing path: registry status revoked, epoch + 1,
     sessions and PSK destroyed, `REVOKE_NOTICE` to the other CHs.
   - It closes the member's CM-role sessions and removes it from every grant.
   - It changes the member's registry role CM → CH, designates it for the cluster (epoch + 1) and
     emits `CH_PROMOTED`.
2. **At the node** (the driver, like the factory/firmware channel used for provisioning):
   - The member's CM-role session keys and ephemerals are destroyed, along with its cached PSK with
     the old CH.
   - The node then runs CH software with its own keystore, which holds only `Pr`. No `k` reaches it:
     the master-key invariant check runs on every step.
3. **Onboarding by the existing steps (§4.6.5):**
   - the new CH's CH–BS key exchange;
   - its `CLUSTER_CLAIM` for the remaining non-revoked members, and the BS's grant;
   - `CLUSTER_OPEN` to the members, then their CM–BS handshakes relayed by the new CH;
   - the BS's `DESIGNATION` naming the new CH. Each member then destroys its sessions and PSK with
     the old CH (follow-up D2) and runs the CM–CH key exchange with the new one.

The old CH is not told, like any revoked device (E-09 D7). Its later handshakes are refused at the
BS's ID check, and frames on its old sessions are rejected, because the BS destroyed those sessions.

This extends §4.6.7's re-designation, which previously required a newly provisioned CH identity
(errata E-14).

### Detection: the "CH suspected" alert (`src/maka/recovery/controller.py`, `monitor.py`)

- **Windows:** 20 scheduler steps. A CH is suspected when the behaviour monitor flags it in **2 of
  the last 3** complete windows. Both numbers can be configured.
- **Detector:** the z-score baseline, implemented in pure Python and fitted on the committed
  behaviour dataset. It gives the same thresholds and flags as `maka.behaviour.detectors`, and a test
  checks this. It needs no `[ml]` extra. It is the detector that sees lossy forwarding; the Isolation
  Forest is nearly blind to it (`docs/BEHAVIOUR.md` §Results).
- **Which windows are scored:** the console scores only windows after the last lifecycle job
  (onboarding, rekey, revocation, designation, reprovisioning, promotion). Those operations are bursts
  that the monitor's steady-state baseline has never seen. Counted from step 0, every freshly
  onboarded CH would look suspected.
- **The alert never acts.** It changes nothing in the network; a test checks this.

### Ranking (`src/maka/recovery/ranking.py`)

For each active, non-revoked member of the cluster, over the last 10 windows:

- **trust** = 1 − mean normalised anomaly score. Each window's score is divided by the detector's
  calibrated CM threshold and clipped to [0, 1]. The detector is the Isolation Forest when the
  `[ml]` extra is installed, otherwise the z-score baseline. The API and the dialog say which was
  used.
- **reliability** = readings accepted at the BS / (accepted + sequence gaps); 0 with no readings.
- **rejections** = rejection events at other devices that name the member as their peer, normalised
  by the largest count among the candidates.

The score is 0.5·trust + 0.4·reliability − 0.1·normalised rejections, with ties broken by identity.
`rank` and `evidence` are pure functions with unit tests. The dialog shows every component, so the
recommendation can be explained.

### Why human-approved by default

A recovery revokes a device and moves a cluster's traffic to another node. An attacker who can make
an honest CH look abnormal, for example by interfering with its members' readings, could trigger
unnecessary recoveries. The monitor's false alarms are rare but not zero.

So the alert only informs. The operator chooses, with the recommendation preselected, and confirms
by typing the cluster label. Viewers see the alert and the candidates, but cannot act.

## Console

- **Topology:** a CH node shows **⚠ CH suspected** when alerted. Selecting a CH shows its recent flags
  and the recommended replacement. **Recover cluster…** (operator) opens the dialog: ranked
  candidates with their components, a typed confirmation, and job progress. Afterwards the cluster is
  drawn under the new CH, with the replaced CH beside it.
- **API:**
  - `GET /api/networks/{id}/recovery` (viewer);
  - the `recover_cluster` job (operator), validated when it is submitted, so a mistake is a 422 and
    not a failed job (a failed job applies the §4.8 recovery rule to the whole network);
  - the lab-only `inject_fault` job: a CH forwards only part of its members' readings, so the alert
    can be demonstrated. Product networks refuse it, and a restart removes the fault.

## Testing

What is tested (`tests/recovery/`, `tests/server/test_recovery_api.py`, `web/e2e/recovery.spec.ts`):

- On `small` and `net`, the promoted member becomes CH and the old CH is revoked. Every remaining
  member is active, designated to the new CH and holds a CM–CH session with it. Readings are
  accepted through the new CH, and other clusters are untouched.
- `k` stays only at the BS. No device other than the old CH keeps session keys or a cached PSK for
  it. The promoted node keeps `Pr` and none of its CM-role session keys.
- Only an active, non-revoked member of the same cluster can be promoted. Refused requests change
  nothing.
- After promotion, the old CH's handshake is refused (`UNAUTHORISED_PEER`) and a batch on its old
  session is rejected (`UNKNOWN_SESSION`).
- The ranking formula, tie-break, edge cases and evidence extraction.
- The pure-Python baseline agrees with the numpy detector.
- An alert on a lossy CH, which never acts; no alerts on honest CHs after onboarding.
- Through the API and the browser: viewers read the status but cannot act, the dialog promotes the
  recommended member, and fault injection is lab-only.

**Not done:** a statistical evaluation (detection delay, recovery time, readings lost, recommended vs
random candidate, false recoveries over many seeds). There are no results to report.

## Limits

- Simulated network, toy parameters in the tests, and our own injected fault (lossy forwarding);
  other failures are untested.
- The promoted node takes on the CH workload (relaying, batching, a CH–BS session) and stops sending
  its own readings.
- An attacker able to make an honest CH look abnormal could trigger unnecessary recoveries; hence the
  operator confirmation.
- In the lossy-forwarding fault, every member is honest. The ranking then mostly reflects which
  members' readings the faulty CH happened to drop, not their own behaviour.
- The alert depends on traffic: an idle cluster produces no evidence.
