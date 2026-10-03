"""M0-T3: re-verify the MAKA_IMPLEMENTATION_REPORT.md claims IMPLEMENTATION_PLAN.md depends on.

Each test asserts the *correct* behaviour. Where the report says the current code is
defective, the test is `xfail(strict=True)` with the gap ID as its reason: it fails today
(confirming the claim) and flips to a hard XPASS failure once the defect is fixed, at which
point it must be converted into a normal regression test.

Claim (f) is the exception: nonce equality across same-seed runs is a consequence of
NFR-REL-02 (seeded determinism), not a defect to be removed -- see docs/PLAN_ERRATA.md.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maka import aead, channel, fixtures, ibe, ledger, params, rng, trace
from maka.protocol import (
    p1_initialization,
    p2_key_generation,
    p3_node_registration,
    p4_node_authentication,
)

pytestmark = pytest.mark.baseline


def _start(tmp_path: Path, run_id: str, seed: int = 7, verbosity: int = 1) -> trace.Tracer:
    rng.seed(seed)
    ledger.current().reset()
    return trace.init(run_id=run_id, out_dir=tmp_path, color=False, verbosity=verbosity)


def _registered_net(tmp_path: Path, run_id: str):
    _start(tmp_path, run_id)
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    return net


def _events(tmp_path: Path, run_id: str) -> list[dict]:
    path = tmp_path / f"{run_id}.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


@pytest.mark.xfail(strict=True, reason="I-02: pseudo-identities are sent in clear (report §4 Q6)")
def test_a_pseudo_frames_are_encrypted(tmp_path: Path) -> None:
    net = _registered_net(tmp_path, "claim-a")
    pseudo = net.channel.eavesdrop("PSEUDO_BS_CH") + net.channel.eavesdrop("PSEUDO_CH_CM")
    assert pseudo
    assert all(isinstance(f.payload, ibe.Ciphertext) for f in pseudo)


@pytest.mark.xfail(strict=True, reason="I-03: BS reads the CH object, never decrypts the beacon")
def test_b_bs_decrypts_beacon(tmp_path: Path) -> None:
    net = _registered_net(tmp_path, "claim-b")
    assert ledger.current().total(net.bs.identity, "registration").get("T_E/D", 0) >= 1


@pytest.mark.xfail(strict=True, reason="I-01: Phase 4 verifies sender in-memory values, not received bytes")
def test_c_tampered_em1_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original_send = channel.Channel.send

    def corrupting_send(self, label, src, dst, payload, body):  # type: ignore[no-untyped-def]
        frame = original_send(self, label, src, dst, payload, body)
        if label == "EM1":
            flipped = bytearray(payload.body)
            flipped[-1] ^= 0x01
            frame.payload = ibe.Ciphertext(u_point=payload.u_point, body=bytes(flipped))
        return frame

    monkeypatch.setattr(channel.Channel, "send", corrupting_send)
    net = _registered_net(tmp_path, "claim-c")
    p4_node_authentication.run(net, fixtures.PAPER)
    trace.active().close()
    cm_accepts_ch = [e for e in _events(tmp_path, "claim-c")
                     if e["type"] == "check" and e["desc"].startswith("CM verifies CH") and e["ok"]]
    assert not cm_accepts_ch


@pytest.mark.xfail(strict=True, reason="I-05: equal IDs give a zero scalar with no exception")
def test_d_xor_to_scalar_rejects_degenerate() -> None:
    r_group = params.get("toy").curve.r_group
    with pytest.raises(ValueError):
        p3_node_registration.xor_to_scalar("X", "X", r_group)


@pytest.mark.xfail(strict=True, reason="I-09: k is printed to the transcript")
def test_e_master_key_not_in_transcript(tmp_path: Path) -> None:
    _start(tmp_path, "claim-e", verbosity=1)
    p = params.get("toy")
    # p1 draws k as the first scalar from the freshly seeded global RNG
    expected_k = rng.Rng(seed=7).below(p.curve.r_group)
    p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    trace.active().close()
    log = (tmp_path / "claim-e.log").read_text(encoding="utf-8")
    assert str(expected_k) not in log


def test_f_aead_nonce_repeats_across_same_seed_runs(tmp_path: Path) -> None:
    """I-10 (confirmed, retained by design in seeded mode -- see docs/PLAN_ERRATA.md)."""
    key = bytes(32)
    nonces = []
    for i in range(2):
        _start(tmp_path, f"claim-f-{i}", seed=99)
        nonces.append(aead.encrypt(key, b"reading")[: aead.NONCE_BYTES])
    assert nonces[0] == nonces[1]
