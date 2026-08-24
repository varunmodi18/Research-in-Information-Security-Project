"""P2 DoD: group axioms, r_group*g = O, (a+b)*P = a*P + b*P, cofactor clearing."""

from __future__ import annotations

import pytest

from maka import params, trace


@pytest.fixture(autouse=True, scope="module")
def _tracer() -> None:
    trace.init(run_id="test-curve", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)


@pytest.mark.parametrize("name", ["toy", "demo", "secure"])
def test_generator_is_on_curve_and_has_order_r(name: str) -> None:
    p = params.get(name)
    assert p.g.is_on_curve()
    assert (p.curve.r_group * p.g).is_infinity()
    assert not p.g.is_infinity()


def test_cofactor_clearing_lands_in_subgroup() -> None:
    p = params.get("toy")
    c = p.curve
    assert c.cofactor * c.r_group == c.order


def test_scalar_mul_distributes_over_addition() -> None:
    p = params.get("toy")
    g = p.g
    a, b = 7, 13
    lhs = (a + b) * g
    rhs = a * g + b * g
    assert lhs == rhs


def test_scalar_mul_associative_like() -> None:
    p = params.get("toy")
    g = p.g
    a, b = 5, 9
    assert a * (b * g) == (a * b) * g


def test_point_addition_group_axioms() -> None:
    p = params.get("toy")
    g = p.g
    a, b, c = 3 * g, 7 * g, 11 * g
    from maka.curve import Point

    o = Point.infinity(p.curve)
    assert a + o == a
    assert a + (-a) == o
    assert a + b == b + a
    assert (a + b) + c == a + (b + c)


def test_scalar_mul_zero_and_identity() -> None:
    p = params.get("toy")
    g = p.g
    assert (0 * g).is_infinity()
    assert (1 * g) == g


def test_r_group_multiple_is_infinity_for_arbitrary_point() -> None:
    p = params.get("toy")
    g = p.g
    h = 999 * g
    assert (p.curve.r_group * h).is_infinity()
