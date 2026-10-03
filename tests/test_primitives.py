"""P4.5 DoD: hash-to-point order, IBE round trip, AEAD tamper detection.
P13.4: H1/H2 are distinct callables and H2 never returns a point (IA-09)."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from maka import aead, hashing, ibe, params, rng, trace


@pytest.fixture(autouse=True)
def _fresh_state() -> None:
    rng.seed(42)
    trace.init(run_id="test-primitives", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)


def test_hash_to_point_lands_in_order_r_subgroup() -> None:
    p = params.get("toy")
    for msg in (b"a", b"node-1", b"node-2", b"", b"x" * 100):
        point = hashing.hash_to_point(p.curve, msg)
        assert point.is_on_curve()
        assert (p.curve.r_group * point).is_infinity()


def test_hash_to_point_deterministic() -> None:
    p = params.get("toy")
    assert hashing.hash_to_point(p.curve, b"same") == hashing.hash_to_point(p.curve, b"same")


def test_h1_and_h2_are_distinct_callables_and_h2_never_returns_a_point() -> None:
    from maka.curve import Point

    assert hashing.hash_to_point is not hashing.h2_point_to_bytes
    p = params.get("toy")
    point = hashing.hash_to_point(p.curve, b"probe")
    out = hashing.h2_point_to_bytes(point, nbytes=32)
    assert isinstance(out, bytes)
    assert not isinstance(out, Point)


@pytest.mark.parametrize("msg", [b"hello world", b"", b"x" * 500])
def test_ibe_round_trip(msg: bytes) -> None:
    p = params.get("toy")
    c, g = p.curve, p.g
    k = rng.current().below(c.r_group)
    k_pub = k * g
    pu_i = hashing.hash_to_point(c, b"node")
    pr_i = k * pu_i
    ct = ibe.encrypt(c, g, msg, pu_i, k_pub)
    pt = ibe.decrypt(c, ct, pr_i)
    assert pt == msg


def test_ibe_wrong_key_fails() -> None:
    p = params.get("toy")
    c, g = p.curve, p.g
    k = rng.current().below(c.r_group)
    k_pub = k * g
    pu_i = hashing.hash_to_point(c, b"node-a")
    pu_j = hashing.hash_to_point(c, b"node-b")
    pr_j = k * pu_j
    ct = ibe.encrypt(c, g, b"secret", pu_i, k_pub)
    with pytest.raises(InvalidTag):
        ibe.decrypt(c, ct, pr_j)


def test_aead_round_trip_and_tamper_detection() -> None:
    key = bytes(range(32))
    blob = aead.encrypt(key, b"payload", ad=b"ad")
    assert aead.decrypt(key, blob, ad=b"ad") == b"payload"
    tampered = blob[:-1] + bytes([blob[-1] ^ 0xFF])
    with pytest.raises(InvalidTag):
        aead.decrypt(key, tampered, ad=b"ad")
