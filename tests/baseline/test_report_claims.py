"""M0-T3: re-verify the MAKA_IMPLEMENTATION_REPORT.md claims IMPLEMENTATION_PLAN.md depends on.

Each test asserts the *correct* behaviour. At M0 (commit 1d01073) claims (a)-(e) were confirmed
as strict xfails. M1 fixed them, they flipped to XPASS, and they are now ordinary regression
tests (see docs/baseline/m1_delta.md). Claim (f) is retained by design in seeded mode
(docs/PLAN_ERRATA.md E-01).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maka import aead, codec, fixtures, ledger, params, rng, trace
from maka.channel import Frame
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


def _registered_net(tmp_path: Path, run_id: str, interceptor=None):  # type: ignore[no-untyped-def]
    _start(tmp_path, run_id)
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    net.channel.interceptor = interceptor
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    return net


def _events(tmp_path: Path, run_id: str) -> list[dict]:
    path = tmp_path / f"{run_id}.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_a_pseudo_frames_are_encrypted(tmp_path: Path) -> None:
    """I-02 fixed (M1-T4): with secure_pseudo_ids (the default) every PSEUDO frame is an IBE
    ciphertext and no pseudo-identity point appears in its bytes (V-ORIG-04)."""
    net = _registered_net(tmp_path, "claim-a")
    ch = next(iter(net.cluster_heads.values()))
    cm = next(iter(net.cluster_members[ch.identity].values()))
    pseudo = net.channel.eavesdrop("PSEUDO_BS_CH") + net.channel.eavesdrop("PSEUDO_CH_CM")
    assert len(pseudo) == 2
    for frame in pseudo:
        codec.decode_ibe(ch.curve, frame.payload)  # parses as an IBE ciphertext
        for secret_point in (ch.p_ch, cm.p_cm):
            assert codec.enc_point(secret_point) not in frame.payload


def test_b_bs_decrypts_beacon(tmp_path: Path) -> None:
    """I-03 fixed (M1-T3): the BS decrypts the delivered beacon."""
    net = _registered_net(tmp_path, "claim-b")
    assert ledger.current().total(net.bs.identity, "registration").get("T_E/D", 0) >= 1


def test_c_tampered_em1_is_rejected(tmp_path: Path) -> None:
    """I-01 fixed (M1-T3): one flipped byte in EM1 on the channel makes the CM reject its CH."""

    def flip_em1(frame: Frame) -> Frame:
        if frame.label != "EM1":
            return frame
        raw = bytearray(frame.payload)  # type: ignore[arg-type]
        raw[-1] ^= 0x01
        return Frame(frame.label, frame.src, frame.dst, bytes(raw), frame.nbits)

    net = _registered_net(tmp_path, "claim-c", interceptor=flip_em1)
    p4_node_authentication.run(net, fixtures.PAPER)
    trace.active().close()
    events = _events(tmp_path, "claim-c")
    assert not [e for e in events if e["type"] == "check"
                and e["desc"].startswith("CM verifies CH") and e["ok"]]
    assert [e for e in events if e["type"] == "event" and e["event"] == "ORIG_AUTH_FAIL"
            and e["actor"] == "CM-0101"]
    cm = next(iter(net.cluster_members["CH-01"].values()))
    assert cm.failed


def test_d_xor_to_scalar_rejects_degenerate() -> None:
    """I-05 fixed (M1-T2)."""
    r_group = params.get("toy").curve.r_group
    with pytest.raises(p3_node_registration.DegenerateScalarError):
        p3_node_registration.xor_to_scalar("X", "X", r_group)


def test_e_master_key_not_in_transcript(tmp_path: Path) -> None:
    """I-09 fixed (M1-T7): k is recorded as «secret:...», never as its value."""
    _start(tmp_path, "claim-e", verbosity=3)
    p = params.get("toy")
    # p1 draws k as the first scalar from the freshly seeded global RNG
    expected_k = rng.Rng(seed=7).randint(1, p.curve.r_group)
    p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    trace.active().close()
    for suffix in (".log", ".jsonl"):
        text = (tmp_path / f"claim-e{suffix}").read_text(encoding="utf-8")
        assert str(expected_k) not in text
        assert f"{expected_k:x}" not in text
    assert "«secret:k (master key)»" in (tmp_path / "claim-e.log").read_text(encoding="utf-8")


def test_f_aead_nonce_repeats_across_same_seed_runs(tmp_path: Path) -> None:
    """I-10 (confirmed, retained by design in seeded mode -- see docs/PLAN_ERRATA.md E-01)."""
    key = bytes(32)
    nonces = []
    for i in range(2):
        _start(tmp_path, f"claim-f-{i}", seed=99)
        nonces.append(aead.encrypt(key, b"reading", ad=b"")[: aead.NONCE_BYTES])
    assert nonces[0] == nonces[1]
