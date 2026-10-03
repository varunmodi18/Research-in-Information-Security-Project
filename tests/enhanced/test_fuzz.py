"""V-FUZZ-01 for the MAKA-E decoders: only DecodeError may escape."""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from maka.codec import DecodeError
from maka.enhanced import messages as m

SAMPLES = [
    m.encode_hs1(b"s" * 16, "CM-1", "CH-1", m.CM_CH, b"n" * 32, b"x" * 8),
    m.hs2_body(b"s" * 16, "CH-1", "CM-1", b"n" * 32, b"y" * 8) + b"t" * 32,
    m.encode_hs3(b"s" * 16, b"t" * 32),
    m.encode_secure(m.DATA_INNER, b"s" * 16, 7, b"c" * 40),
    m.encode_relay("BS-01", b"\x02\x10abc"),
    m.encode_open("CH-01", 3),
    m.encode_data_cm(b"s" * 16, b"inner", b"t" * 32),
    m.encode_session_unknown(b"s" * 16, "CH-1", "CM-1"),
]

inputs = st.one_of(
    st.binary(max_size=300),
    st.tuples(st.sampled_from(SAMPLES), st.integers(0, 400), st.integers(0, 255)).map(
        lambda t: t[0][: t[1] % (len(t[0]) + 1)] + bytes([t[2]]) + t[0][t[1] % (len(t[0]) + 1) + 1:]),
    st.tuples(st.sampled_from([0x01, 0x02]), st.sampled_from(list(m.LABELS)), st.binary(max_size=200)).map(
        lambda t: bytes([t[0], t[1]]) + t[2]),
)


def _only_decode_errors(data: bytes) -> None:
    for name, decoder in m.DECODERS.items():
        try:
            decoder(data)
        except DecodeError:
            pass
        except Exception as exc:
            raise AssertionError(f"{name}: {type(exc).__name__}: {exc}") from exc
    m.label(data)
    for raw in (data,):
        for fn in (m.decode_grant, m.decode_epoch_id, m.decode_batch, m.dec_ids):
            try:
                fn(raw)
            except DecodeError:
                pass


@settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(inputs)
def test_enhanced_decoders_quick(data: bytes) -> None:
    _only_decode_errors(data)


@pytest.mark.slow
@settings(max_examples=10_000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(inputs)
def test_enhanced_decoders_full(data: bytes) -> None:
    _only_decode_errors(data)
