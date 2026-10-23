# Behavioural monitoring (experimental)

**Experimental. Alerts only. Simulated data.** This layer is not part of RP9 or of MAKA-E's security
argument (register IA-19).

## Purpose

MAKA-E establishes *who* a device is. It cannot stop a device that holds valid keys from *behaving*
abnormally. `docs/RESIDUAL_RISKS.md` names two such cases:

- **R-07**: an authorised device can make its peers do public-key work by starting handshakes;
- **R-12**: a cluster head can drop its members' readings (it cannot read or forge them).

This layer looks for that kind of abnormal device behaviour. It runs at the base station on data the
system already records: frames and security events. It only raises alerts. It never revokes, rekeys or
blocks anything, and an alert is not proof of misbehaviour.

The abnormal behaviour it is evaluated on is **faults we inject into our own simulator**. The results
say how these detectors behave on that data and nothing about real deployments. Nothing here prevents
anything, and nothing here is proven.

## Features

`src/maka/behaviour/features.py` computes, for each CM and CH and each window of W = 20 scheduler
steps, counts of public metadata only. It is a pure function of the step log and the event list, and is
unit-tested on a hand-built log.

| Feature | Counted from |
|---|---|
| `frames_sent`, `frames_received` | frames the device put on the channel / had delivered to it |
| `handshakes_initiated` | HS1 messages naming the device as initiator (direct, or relayed via its CH) |
| `handshakes_completed` | `KEY_CONFIRMED` (initiator) plus `HANDSHAKE_OK` (responder) at the device |
| `rekeys` | `KEY_ROTATED` at the device (each rotation also emits one `SESSION_SUPERSEDED`) |
| `rejections` | events at the device whose type is a rejection reason code |
| `readings_accepted_at_bs` | `DATA_ACCEPTED` at the BS for this CM |
| `seq_gaps_at_bs` | inner sequence numbers missing before an accepted reading, per CM session; counted for the CM and for the CH that forwarded it |
| `batch_items_forwarded` | items in the CH's `BATCH_SENT` events |

## Data generation

`src/maka/behaviour/traffic.py` runs an unmodified MAKA-E network on a lab bus with toy parameters. It
adds three kinds of benign variation, all set in one `TrafficConfig`:

- cluster heads start onboarding in random order at random offsets, and each CH's members onboard in
  random order;
- readings come at jittered intervals (30 ± 10 steps);
- each CM occasionally rekeys (probability 1/300 per step).

A `Fault` makes **one** device behave abnormally for steps 200–500 of the 600 observed steps. It is
the ground truth for the labels:

| Fault | Variant | Behaviour |
|---|---|---|
| `excessive_rekey` | `default` | one CM rekeys every 5 steps (normal: every 300 on average) |
| `excessive_rekey` | `near_normal` | one CM rekeys every 150 steps, only slightly more often than normal |
| `lossy_forwarding` | `default` | one CH forwards only 70 % of its members' readings in its batches |

Every frame stays protocol-valid. There is no adversary on the channel.

`src/maka/behaviour/dataset.py` produces the following on the `small` (1 CH × 3 CM) and `net`
(3 CH × 3 CM) topologies:

- 40 benign runs per topology;
- 10 runs per fault variant per topology.

That is 140 runs and 33,600 device-windows. A window is labelled abnormal when it belongs to the faulty
device and overlaps the fault span (900 windows). The output is `artifacts/behaviour/dataset.csv` (CSV,
to avoid a new dependency) and `manifest.json`, which records every seed and the full configuration.

## Detectors

`src/maka/behaviour/detectors.py` needs the optional `[ml]` extra (IA-18). Both detectors are trained
per role (CM, CH) on benign training windows only:

- **z-score baseline**: per-feature mean and standard deviation. The score is the largest absolute
  z-score. σ is floored at 0.5 (half a count), because a feature that never varies in training would
  otherwise give an infinite z-score.
- **Isolation Forest**: scikit-learn, 200 trees, fixed seed. The score is `-score_samples`.

Each threshold is the 99th percentile of the scores on benign validation windows (an observed score,
`method="higher"`). A window is flagged when its score is strictly above the threshold, so at most
1 % of the validation windows are flagged.

## Evaluation protocol

`src/maka/behaviour/evaluate.py` splits **by run**, so no seed is in two splits:

- **benign runs**: shuffled per topology with a fixed seed into train / validation / test (60/20/20,
  that is 24/8/8 runs per topology);
- **fault runs**: test only.

For each fault variant and detector it reports:

- precision, recall and F1 over all device-windows of that variant's test runs;
- false alarms per 1,000 of the other (non-faulty) windows in those runs;
- the number of runs with at least one alert on the faulty device during the fault;
- the median detection delay, in windows from the start of the fault to the first such alert.

False alarms per 1,000 device-windows on the benign test runs are reported per detector. Each
Isolation Forest alert is explained by its three features with the largest z-scores.

## Results (2026-10-23, `artifacts/behaviour/results_2026-10-23.{json,md}`)

| Injected fault | Detector | Precision | Recall | F1 | False alarms /1k (other windows) | Detected runs | Median delay (windows) |
|---|---|---:|---:|---:|---:|---:|---:|
| excessive rekey | z-score baseline | 0.504 | 0.473 | 0.488 | 31.1 | 13/20 | 0 |
| excessive rekey | Isolation Forest | 0.476 | 0.523 | 0.498 | 38.4 | 16/20 | 0 |
| excessive rekey, near normal | z-score baseline | 0.100 | 0.007 | 0.013 | 4.0 | 2/20 | 0 |
| excessive rekey, near normal | Isolation Forest | 0.203 | 0.040 | 0.067 | 10.4 | 10/20 | 0 |
| lossy forwarding | z-score baseline | 0.610 | 0.120 | 0.201 | 5.1 | 19/20 | 5 |
| lossy forwarding | Isolation Forest | 0.102 | 0.017 | 0.029 | 9.8 | 4/20 | 11 |

False alarms on the benign test runs: z-score baseline 2.3 and Isolation Forest 8.3 per 1,000
device-windows. Both are within the 1 % target. Both are higher on `small` (7.3 and 26.0) than on `net`
(0.7 and 2.4), because one threshold per role is shared by both topologies.

**The simple baseline is clearly better on lossy forwarding. On excessive rekeying the two are about
even, with the Isolation Forest slightly ahead.** The samples are small: 20 fault runs per variant and 16
benign test runs. A different random stream used during development gave noticeably different numbers
(for example, 19/20 detected runs for the baseline on excessive rekeying). Differences of a few points
between the detectors are therefore not meaningful.

- **Excessive rekeying:** the two detectors are close. The F1 scores are 0.49 and 0.50. The Isolation
  Forest has higher recall and detects 16 of 20 runs, against 13 of 20 for the baseline. The baseline has
  higher precision and fewer false alarms.

  The faulty CM's handshake, rekey and frame counts stand far outside normal. In detected runs, both
  detectors alert in the first fault window. The Isolation Forest scores the features jointly. All 22
  faulty windows that only it flags have four or five features above z = 2. Their largest z, however,
  sits exactly at the baseline's CM threshold (5.38): a benign validation window scored the same, and the
  baseline flags only scores strictly above the threshold.

  Precision stays near 0.5 for two reasons:
  - the faulty CM's CH relays and completes all those handshakes;
  - on the shared channel, other devices' traffic shifts too.

  Those windows are labelled normal, because the ground truth names only the faulty device. They count
  as false alarms (31–38 per 1,000 other windows) even though the behaviour behind them really changed.
- **Near-normal variant:** both detectors miss almost every faulty window (recall 0.01 and 0.04). One
  extra rekey every 150 steps looks like the occasional legitimate rekey. The Isolation Forest's 10/20
  detected runs come with more false alarms (10.4 against 4.0 per 1,000), so neither detector can tell
  this variant from normal behaviour. This variant is there to show the limit.
- **Lossy forwarding:** the baseline alerts in 19 of 20 runs (median delay 5 windows) at precision 0.61.
  Recall per window is low (0.12): a single missing reading gives z = 2, below the CH threshold of about
  3.6, so the baseline needs a window with two or more gaps.

  The Isolation Forest alerts in only 4 of 20 runs. `seq_gaps_at_bs` is always 0 in benign training,
  and an Isolation Forest cannot split on a feature that never varies, so the one feature that shows
  loss is invisible to it. Its few correct alerts come from other counts (rekeys, frames). The floored σ
  of the baseline turns any gap into a large z-score.

  `tests/behaviour/test_detectors_evaluate.py::test_zscore_flags_a_feature_unseen_in_training`
  shows this behaviour on a constructed example.

## Limitations

- Simulated data only: toy parameters, one frame per scheduler step, no radio loss or timing realism.
- The faults are ours and were chosen by us. Other abnormal behaviour is untested, and a device that
  stays close to normal behaviour (the near-normal variant) is mostly not detected.
- Alerts only: the monitor never revokes, rekeys or blocks a device, and an alert is not proof of
  misbehaviour.
- Thresholds are set for 1 % false alarms on benign validation windows. Real traffic would need its
  own data and recalibration.
- Small samples: results vary noticeably with the random stream (see Results), so differences of a few
  points between the detectors are not meaningful.
- Not in scope: a live dashboard, deep learning, detection of falsified readings, automatic
  responses, and monitoring of product networks.

## Regenerating

```bash
pip install -e ".[ml]"           # numpy, scikit-learn (pinned to a minor version)
python -m maka.behaviour all     # build -> train -> evaluate; or `make behaviour`
```

`build` writes `dataset.csv` and `manifest.json` (about 35 s). `train` writes `model.joblib`, which is
not committed. `evaluate` writes `results_<date>.{json,md}`.

Tests check that the artefacts are reproducible:

- `test_committed_dataset_is_regenerable` (slow) rebuilds the dataset byte for byte;
- `test_committed_results_match_the_committed_dataset` retrains and re-evaluates to exactly the
  committed results.

The console's Evaluation page shows the latest committed results under "Behavioural monitoring
(experimental)".
