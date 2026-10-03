"""M1: defect fixes on the legacy reference path (IMPLEMENTATION_PLAN.md M1-T2..T8).

V-UNIT-06, V-UNIT-08, V-ORIG-01..06 (legacy-path variants), the M1-T5 tampered-EM3 exclusion,
and the I-16 lint rule (no protocol `assert` outside type narrowing).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from maka import aead, codec, fixtures, ledger, params, rng, trace
from maka.channel import Frame
from maka.network import Network
from maka.protocol import (
    data_transmission,
    p1_initialization,
    p2_key_generation,
    p3_node_registration,
    p4_node_authentication,
    p5_session_key_agreement,
)
from maka.protocol.p3_node_registration import DegenerateScalarError, xor_to_scalar

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _fresh(tmp_path: Path) -> None:
    rng.seed(4242)
    ledger.current().reset()
    trace.init(run_id="test-legacy", out_dir=tmp_path, color=False, verbosity=1)


def _run(fixture: str, *, secure: bool = True, interceptor=None, until: int = 6) -> Network:  # type: ignore[no-untyped-def]
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixture)
    net.channel.interceptor = interceptor
    phases = [
        lambda: p2_key_generation.run(net),
        lambda: p3_node_registration.run(net, fixture, secure_pseudo_ids=secure),
        lambda: p4_node_authentication.run(net, fixture),
        lambda: p5_session_key_agreement.run(net, fixture),
        lambda: data_transmission.run(net),
    ]
    for phase in phases[: until - 1]:
        phase()
    return net


def _flip_last_byte(label: str, src: str | None = None):  # type: ignore[no-untyped-def]
    def interceptor(frame: Frame) -> Frame:
        if frame.label != label or (src is not None and frame.src != src):
            return frame
        raw = bytearray(frame.payload)  # type: ignore[arg-type]
        raw[-1] ^= 0x01
        return Frame(frame.label, frame.src, frame.dst, bytes(raw), frame.nbits)
    return interceptor


# -- V-UNIT-06 ---------------------------------------------------------------------

def test_v_unit_06_xor_to_scalar() -> None:
    r_group = params.get("toy").curve.r_group
    assert xor_to_scalar("BS-01", "CH-01", r_group) == xor_to_scalar("CH-01", "BS-01", r_group)
    with pytest.raises(DegenerateScalarError):
        xor_to_scalar("CH-01", "CH-01", r_group)
    raw = int.from_bytes(bytes(a ^ b for a, b in zip(codec.id_field("CH-01"), codec.id_field("CM-0101"))), "big")
    with pytest.raises(DegenerateScalarError):
        xor_to_scalar("CH-01", "CM-0101", raw)  # an r_group dividing the XOR makes it 0


def test_xor_uses_fixed_160_bit_fields() -> None:
    """IA-13: right-padded 20-byte fields, so the value differs from the old integer XOR."""
    r_group = params.get("toy").curve.r_group
    old = (int.from_bytes(b"CH-01", "big") ^ int.from_bytes(b"CM-0101", "big")) % r_group
    assert xor_to_scalar("CH-01", "CM-0101", r_group) != old


# -- V-UNIT-08 -------------------------------------------------------------------------

def test_v_unit_08_aead_ad_nonce_tamper() -> None:
    key = bytes(range(32))
    ad = data_transmission.data_ad("CM-0101", "BS-01", 1)
    blob = aead.encrypt(key, b"reading", ad=ad, nonce=aead.counter_nonce(1))
    assert aead.decrypt(key, blob, ad=ad) == b"reading"
    bad_ad = ad[:-1] + bytes([ad[-1] ^ 0x01])
    with pytest.raises(InvalidTag):
        aead.decrypt(key, blob, ad=bad_ad)
    with pytest.raises(InvalidTag):
        aead.decrypt(key, blob[:-1] + bytes([blob[-1] ^ 0x80]), ad=ad)
    nonces = {aead.counter_nonce(seq) for seq in range(1, 100_001)}
    assert len(nonces) == 100_000
    with pytest.raises(ValueError):
        aead.counter_nonce(0)


# -- V-ORIG-01..03 (legacy path) ------------------------------------------------------

@pytest.mark.parametrize("fixture", [fixtures.PAPER, fixtures.SMALL, fixtures.NET])
def test_v_orig_01_03_honest_runs_authenticate_everyone(fixture: str) -> None:
    net = _run(fixture)
    for ch in net.cluster_heads.values():
        assert not ch.failed
        for cm in net.cluster_members[ch.identity].values():
            assert not cm.failed and cm.ch_verified and cm.identity in ch.authenticated_members
            assert cm.identity in net.sym_keys
    assert len(net.channel.eavesdrop("DATA_CM")) == len(net.all_members())


# -- V-ORIG-04: covered by tests/baseline/test_report_claims.py::test_a --------------------

def test_v_orig_04_no_secure_mode_sends_clear_points() -> None:
    net = _run(fixtures.PAPER, secure=False, until=3)
    ch = net.cluster_heads["CH-01"]
    frame = net.channel.eavesdrop("PSEUDO_BS_CH")[0]
    assert codec.enc_point(ch.p_ch) in frame.payload  # the documented paper-reproduction mode


# -- V-ORIG-05 ------------------------------------------------------------------------

def test_v_orig_05_bs_output_independent_of_ch_object_state() -> None:
    clean = _run(fixtures.PAPER, until=3)
    expected = dict(clean.bs.pseudo_ids)

    rng.seed(4242)
    ledger.current().reset()
    holder: dict[str, Network] = {}

    def corrupt_after_beacon(frame: Frame) -> Frame:
        if frame.label == "BEACON":
            ch = holder["net"].cluster_heads["CH-01"]
            # A BS that read CH object state (I-03) would now register EVIL-1 as a member.
            ch.members = {**ch.members, "EVIL-1": ch.curve_g}
            ch.identity_field = "EVIL"
        return frame

    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    holder["net"] = net
    net.channel.interceptor = corrupt_after_beacon
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    assert net.bs.pseudo_ids == expected
    assert "EVIL-1" not in net.bs.pseudo_ids


# -- V-ORIG-06 ------------------------------------------------------------------------

@pytest.mark.parametrize("n", [1, 2, 3])
def test_v_orig_06_ch_ledger_formula(n: int) -> None:
    net = _run(f"custom-1x{n}", secure=False, until=4)
    auth = ledger.current().total("CH-01", "authentication")
    assert auth.get("T_SM", 0) == 2 + n  # A1, A2, n x A4'
    assert auth.get("T_E/D", 0) == n + 1 + n  # n EM1, 1 EM2, n EM3 decryptions
    assert len(net.channel.eavesdrop("EM2")) == 1
    assert len(net.channel.eavesdrop("EM1")) == n


def test_secure_pseudo_ids_cost_matches_ob07() -> None:
    """OB-07: secure delivery adds n+1 T_E/D at the CH, 1 at each CM, 1 T_E/D + 1 T_HG at the BS."""
    _run("custom-1x2", secure=True, until=3)
    secure = {e: ledger.current().total(e, "registration") for e in ("CH-01", "CM-0101", "BS-01")}
    rng.seed(4242)
    ledger.current().reset()
    _run("custom-1x2", secure=False, until=3)
    plain = {e: ledger.current().total(e, "registration") for e in ("CH-01", "CM-0101", "BS-01")}
    assert secure["CH-01"]["T_E/D"] - plain["CH-01"]["T_E/D"] == 2 + 1
    assert secure["CM-0101"].get("T_E/D", 0) - plain["CM-0101"].get("T_E/D", 0) == 1
    assert secure["BS-01"]["T_E/D"] - plain["BS-01"]["T_E/D"] == 1
    assert secure["BS-01"].get("T_HG", 0) - plain["BS-01"].get("T_HG", 0) == 1


# -- M1-T5: failures are enforced ------------------------------------------------------------

def test_tampered_em3_excludes_cm_from_data() -> None:
    net = _run(fixtures.SMALL, interceptor=_flip_last_byte("EM3", src="CM-0102"))
    bad = net.cluster_members["CH-01"]["CM-0102"]
    assert bad.failed and "EM3 rejected" in (bad.failure_reason or "")
    assert "CM-0102" not in net.sym_keys
    senders = {f.src for f in net.channel.eavesdrop("DATA_CM")}
    assert senders == {"CM-0101", "CM-0103"}


def test_tampered_em2_fails_the_cluster() -> None:
    net = _run(fixtures.PAPER, interceptor=_flip_last_byte("EM2"))
    assert net.cluster_heads["CH-01"].failed
    assert net.channel.eavesdrop("DATA_CM") == []


def test_dropped_em1_fails_only_that_member() -> None:
    def drop(frame: Frame) -> Frame | None:
        return None if frame.label == "EM1" and frame.dst == "CM-0101" else frame

    net = _run(fixtures.SMALL, interceptor=drop)
    assert net.cluster_members["CH-01"]["CM-0101"].failed
    assert not net.cluster_members["CH-01"]["CM-0102"].failed


# -- I-16 lint rule ------------------------------------------------------------------------------

PROTOCOL_DIRS = ["src/maka/protocol", "src/maka/runtime", "src/maka/original_rt", "src/maka/enhanced"]


def test_no_protocol_asserts_outside_type_narrowing() -> None:
    offenders = []
    for d in PROTOCOL_DIRS:
        for f in sorted((REPO_ROOT / d).rglob("*.py")) if (REPO_ROOT / d).exists() else []:
            lines = f.read_text(encoding="utf-8").splitlines()
            for node in ast.walk(ast.parse("\n".join(lines))):
                if isinstance(node, ast.Assert) and "type narrowing only" not in lines[node.lineno - 1]:
                    offenders.append(f"{f.relative_to(REPO_ROOT)}:{node.lineno}")
    assert not offenders, f"protocol checks must raise, not assert (python -O strips asserts): {offenders}"
