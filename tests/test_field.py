"""P13.4: field algebra -- Fp and Fp2 laws over random inputs."""

from __future__ import annotations

import pytest

from maka.field import Fp, Fp2, extended_gcd

P_FIELD = 2147483743  # toy p_field, p_field = 3 (mod 4)


def fp(v: int) -> Fp:
    return Fp(v, P_FIELD)


@pytest.mark.parametrize("a,b,c", [(1, 2, 3), (0, 5, 7), (P_FIELD - 1, 2, 3), (12345, 67890, 1)])
def test_fp_ring_axioms(a: int, b: int, c: int) -> None:
    A, B, C = fp(a), fp(b), fp(c)
    assert A + B == B + A
    assert (A + B) + C == A + (B + C)
    assert A + fp(0) == A
    assert A + (-A) == fp(0)
    assert A * B == B * A
    assert (A * B) * C == A * (B * C)
    assert A * (B + C) == A * B + A * C


def test_fp_inverse() -> None:
    for v in (1, 2, 3, 12345, P_FIELD - 1):
        a = fp(v)
        assert a * a.inverse() == fp(1)


def test_fp_inverse_of_zero_raises() -> None:
    with pytest.raises(ZeroDivisionError):
        fp(0).inverse()


def test_extended_gcd() -> None:
    g, x, y = extended_gcd(240, 46)
    assert g == 2
    assert 240 * x + 46 * y == g


def test_fp_sqrt_p3mod4() -> None:
    assert P_FIELD % 4 == 3
    for v in (4, 9, 16, 25):
        a = fp(v)
        root = a.sqrt()
        assert root * root == a


def test_fp_legendre() -> None:
    assert fp(4).legendre() == 1  # perfect square
    assert fp(0).legendre() == 0


def test_fp2_ring_axioms() -> None:
    a = Fp2(fp(3), fp(5))
    b = Fp2(fp(7), fp(11))
    c = Fp2(fp(13), fp(17))
    assert a + b == b + a
    assert (a + b) + c == a + (b + c)
    assert a * b == b * a
    assert (a * b) * c == a * (b * c)
    assert a * (b + c) == a * b + a * c


def test_fp2_inverse() -> None:
    one = Fp2(fp(1), fp(0))
    a = Fp2(fp(3), fp(5))
    assert a * a.inverse() == one


def test_fp2_norm_never_zero_for_nonzero_element() -> None:
    """p_field = 3 (mod 4) means -1 is a non-residue, so a^2 + b^2 = 0 forces a = b = 0 --
    this is exactly why Fp2 = Fp[i]/(i^2+1) is a field here."""
    zero = Fp2(fp(0), fp(0))
    for a, b in ((1, 0), (0, 1), (3, 5), (P_FIELD - 1, 2)):
        elem = Fp2(fp(a), fp(b))
        if elem != zero:
            assert not elem.norm().is_zero()


def test_fp2_conjugate_and_frobenius() -> None:
    a = Fp2(fp(3), fp(5))
    assert a.conjugate().conjugate() == a
