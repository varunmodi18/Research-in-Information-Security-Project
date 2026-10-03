"""M1-T1: codec round trips and rejections (V-UNIT-01..05) and decoder fuzzing (V-FUZZ-01)."""

from __future__ import annotations

import hashlib

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from maka import codec, ibe, ledger, params, rng, trace
from maka.codec import DecodeError
from maka.curve import Point
from maka.field import Fp


@pytest.fixture(autouse=True)
def _fresh(tmp_path) -> None:  # type: ignore[no-untyped-def]
    rng.seed(11)
    trace.init(run_id="test-codec", out_dir=tmp_path, color=False, verbosity=1)


def _toy():  # type: ignore[no-untyped-def]
    return params.get("toy")


def _off_subgroup_point(curve) -> Point:  # type: ignore[no-untyped-def]
    """Hash-to-curve *without* cofactor clearing, until the point lies outside the subgroup."""
    counter = 0
    while True:
        digest = hashlib.sha256(b"off-subgroup" + counter.to_bytes(4, "big")).digest()
        x = Fp(int.from_bytes(digest, "big") % curve.p_field, curve.p_field)
        rhs = x * x * x + Fp(curve.a, curve.p_field) * x + Fp(curve.b, curve.p_field)
        if rhs.legendre() == 1:
            pt = Point(x, rhs.sqrt(), curve)
            if not pt.scalar_mul_unaccounted(curve.r_group).is_infinity():
                return pt
        counter += 1


def test_v_unit_01_point_round_trip() -> None:
    p = _toy()
    r = rng.current()
    for _ in range(100):
        pt = (r.below(p.curve.r_group - 1) + 1) * p.g
        assert codec.dec_point(p.curve, codec.enc_point(pt)) == pt


def test_v_unit_02_rejects_off_curve_infinity_and_lengths() -> None:
    p = _toy()
    good = codec.enc_point(5 * p.g)
    off_curve = good[:-1] + bytes([good[-1] ^ 0x01])
    for bad in (off_curve, bytes(len(good)), good[:-1], good + b"\x00"):
        with pytest.raises(DecodeError):
            codec.dec_point(p.curve, bad)
    with pytest.raises(ValueError):
        codec.enc_point(Point.infinity(p.curve))


def test_v_unit_03_rejects_point_outside_subgroup() -> None:
    p = _toy()
    pt = _off_subgroup_point(p.curve)
    assert pt.is_on_curve()
    assert not pt.scalar_mul_unaccounted(p.curve.r_group).is_infinity()
    with pytest.raises(DecodeError, match="subgroup"):
        codec.dec_point(p.curve, codec.enc_point(pt))


def test_subgroup_check_is_counted_as_t_sm_val_not_t_sm() -> None:
    p = _toy()
    encoded = codec.enc_point(3 * p.g)
    ledger.current().reset()
    with ledger.LedgerScope("X", "decode"):
        codec.dec_point(p.curve, encoded)
    assert ledger.current().total("X", "decode") == {"T_SM_val": 1}


def test_v_unit_04_unlp_rejects_truncation_and_trailing_bytes() -> None:
    blob = codec.LP(b"ab", b"", b"xyz")
    assert codec.unLP(blob, 3) == [b"ab", b"", b"xyz"]
    for bad in (blob[:-1], blob[:1], blob + b"\x00"):
        with pytest.raises(DecodeError):
            codec.unLP(bad, 3)
    with pytest.raises(DecodeError):
        codec.unLP(blob, 2)


@pytest.mark.parametrize("bad", ["", "A" * 21, "bad id", "CM_01", "é", "ID\x00"])
def test_v_unit_05_enc_id_rejects_invalid(bad: str) -> None:
    with pytest.raises(ValueError):
        codec.enc_id(bad)


def test_enc_id_accepts_valid_ids() -> None:
    for ok in ("A", "CM-0101", "x" * 20):
        assert codec.dec_id(codec.enc_id(ok)) == ok


def test_message_round_trips() -> None:
    p = _toy()
    c, g = p.curve, p.g
    pts = [(i + 2) * g for i in range(4)]
    nonce = bytes(range(20))
    beacon = codec.decode_beacon(c, codec.encode_beacon("CH-01", [("CM-1", pts[0]), ("CM-2", pts[1])], nonce))
    assert beacon.id_ch == "CH-01" and beacon.members == [("CM-1", pts[0]), ("CM-2", pts[1])]
    assert beacon.n_reg == nonce
    assert codec.decode_pseudo_bs_ch(c, codec.encode_pseudo_bs_ch(pts[2], [pts[3], pts[0]])) == (
        pts[2], [pts[3], pts[0]])
    assert codec.decode_pseudo_ch_cm(c, codec.encode_pseudo_ch_cm("CH-01", pts[0])) == ("CH-01", pts[0])
    assert codec.decode_auth(c, codec.encode_auth(pts[0], pts[1], nonce)) == (pts[0], pts[1], nonce)
    assert codec.decode_pub(c, codec.encode_pub(pts[3])) == pts[3]
    ct = ibe.Ciphertext(u_point=pts[1], body=b"\x01\x02")
    assert codec.decode_ibe(c, codec.encode_ibe(ct)) == ct
    assert codec.decode_data(codec.encode_data(7, b"blob")) == (7, b"blob")


def test_wrong_version_or_type_rejected() -> None:
    p = _toy()
    msg = codec.encode_pub(p.g)
    with pytest.raises(DecodeError, match="version"):
        codec.decode_pub(p.curve, bytes([0x02]) + msg[1:])
    with pytest.raises(DecodeError, match="type"):
        codec.decode_auth(p.curve, msg)


# -- V-FUZZ-01 ----------------------------------------------------------------

def _valid_samples() -> list[bytes]:
    p = _toy()
    g = p.g
    n = bytes(20)
    return [
        codec.encode_pub(2 * g),
        codec.encode_beacon("CH-01", [("CM-1", 3 * g)], n),
        codec.encode_pseudo_bs_ch(4 * g, [5 * g]),
        codec.encode_pseudo_ch_cm("CH-01", 6 * g),
        codec.encode_auth(7 * g, 8 * g, n),
        codec.encode_ibe(ibe.Ciphertext(u_point=9 * g, body=b"x" * 16)),
    ]


def _assert_only_decode_error(data: bytes) -> None:
    curve = _toy().curve
    for name, decoder in codec.DECODERS.items():
        try:
            decoder(curve, data)
        except DecodeError:
            pass
        except Exception as exc:
            raise AssertionError(f"{name} raised {type(exc).__name__}: {exc}") from exc


_inputs = st.one_of(
    st.binary(max_size=300),
    st.tuples(st.sampled_from(_valid_samples()), st.integers(0, 400), st.integers(0, 255)).map(
        lambda t: t[0][: t[1] % (len(t[0]) + 1)] + bytes([t[2]]) + t[0][t[1] % (len(t[0]) + 1) + 1:]),
    st.tuples(st.sampled_from([0x01, 0x02]), st.integers(1, 7), st.binary(max_size=300)).map(
        lambda t: bytes([t[0], t[1]]) + t[2]),
)


@settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(_inputs)
def test_v_fuzz_01_quick(data: bytes) -> None:
    _assert_only_decode_error(data)


@pytest.mark.slow
@settings(max_examples=10_000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(_inputs)
def test_v_fuzz_01_full(data: bytes) -> None:
    _assert_only_decode_error(data)
