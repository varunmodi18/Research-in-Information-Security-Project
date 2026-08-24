"""Elliptic curve group arithmetic: E: y^2 = x^3 + x over F_p_field.

Realises: RP9 §2.1 (abstract additive cyclic group G, generator g), instantiated per IA-02
as a supersingular curve with p_field = 3 (mod 4), #E(F_p_field) = p_field + 1.

P2.3: Point in affine coordinates (deliberately, not projective -- projective would obscure
      the arithmetic this project exists to make visible).
P2.4: addition, doubling, negation, infinity, with slopes printed at high verbosity.
P2.5: scalar multiplication by double-and-add, MSB-first. Every protocol scalar is drawn from
      Z_r_group (IA-02's consequential substitution for RP9's Z_p), never from Z_p_field.
"""

from __future__ import annotations

from dataclasses import dataclass

from maka import ledger, trace
from maka.field import Fp

FieldElement = object  # Fp or Fp2; kept untyped here to avoid a curve<->field2 circular import


def small_const(sample: FieldElement, value: int) -> FieldElement:
    """Builds the field element `value` (a small non-negative int, e.g. curve coefficient a or
    b) in whatever field `sample` belongs to, via repeated addition -- so curve arithmetic
    works identically whether coordinates are Fp (a G1 point) or Fp2 (a distorted point used
    only inside the pairing), without hardcoding Fp construction here."""
    zero = sample - sample  # type: ignore[operator]
    one = sample / sample  # type: ignore[operator]
    acc = zero
    for _ in range(value):
        acc = acc + one  # type: ignore[operator]
    return acc


@dataclass(frozen=True)
class CurveParams:
    p_field: int  # base-field modulus, p_field = 3 (mod 4)
    a: int  # curve coefficient: y^2 = x^3 + a*x + b  (RP9's curve: a=1, b=0)
    b: int
    order: int  # #E(F_p_field) = p_field + 1 for this supersingular family
    r_group: int  # prime order of the working subgroup G = E(F_p_field)[r_group]
    cofactor: int  # order // r_group


@dataclass(frozen=True)
class Point:
    """A point on E(F_p_field) in affine coordinates, or the point at infinity."""

    x: Fp | None
    y: Fp | None
    params: CurveParams

    @staticmethod
    def infinity(params: CurveParams) -> "Point":
        return Point(None, None, params)

    def is_infinity(self) -> bool:
        return self.x is None

    def is_on_curve(self) -> bool:
        if self.is_infinity():
            return True
        assert self.x is not None and self.y is not None
        a_elem = small_const(self.x, self.params.a)
        b_elem = small_const(self.x, self.params.b)
        lhs = self.y * self.y
        rhs = (self.x * self.x * self.x) + (a_elem * self.x) + b_elem
        return lhs == rhs

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return NotImplemented
        if self.is_infinity() or other.is_infinity():
            return self.is_infinity() == other.is_infinity()
        return self.x == other.x and self.y == other.y

    def __neg__(self) -> "Point":
        if self.is_infinity():
            return self
        assert self.y is not None
        return Point(self.x, -self.y, self.params)

    @ledger.counts("T_PA")
    def __add__(self, other: "Point") -> "Point":
        result = self._add_impl(other)
        assert result.is_on_curve(), "point addition left the curve -- arithmetic bug"
        return result

    def _add_impl(self, other: "Point") -> "Point":
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self
        assert self.x is not None and self.y is not None and other.x is not None and other.y is not None
        if self.x == other.x:
            if self.y == other.y and not self.y.is_zero():
                return self._double_impl()
            return Point.infinity(self.params)  # self == -other
        slope = (other.y - self.y) / (other.x - self.x)
        x3 = slope * slope - self.x - other.x
        y3 = slope * (self.x - x3) - self.y
        t = trace.active()
        if t.verbosity >= 3:
            t.value("slope (add)", trace.render(slope, t.verbosity))
        return Point(x3, y3, self.params)

    def _double_impl(self) -> "Point":
        assert self.x is not None and self.y is not None
        three = small_const(self.x, 3)
        a_elem = small_const(self.x, self.params.a)
        two_y = self.y + self.y
        slope = (self.x * self.x * three + a_elem) / two_y
        x3 = slope * slope - self.x - self.x
        y3 = slope * (self.x - x3) - self.y
        t = trace.active()
        if t.verbosity >= 3:
            t.value("slope (dbl)", trace.render(slope, t.verbosity))
        return Point(x3, y3, self.params)

    @ledger.counts("T_SM")
    def __rmul__(self, scalar: int) -> "Point":
        """Scalar multiplication scalar * self, double-and-add MSB-first (IA-02: scalar in Z_r_group)."""
        if scalar < 0:
            return (-scalar) * (-self)
        result = Point.infinity(self.params)
        addend = self
        t = trace.active()
        bits = bin(scalar)[2:] if scalar > 0 else "0"
        for i, bit in enumerate(bits):
            if t.verbosity >= 3:
                t.step("scalar_mul", f"bit {i}/{len(bits)}: {'DBL+ADD' if bit == '1' else 'DBL'}")
            result = result._add_impl(result)
            ledger.bump("T_PA")
            if bit == "1":
                result = result._add_impl(addend)
                ledger.bump("T_PA")
        assert result.is_on_curve()
        return result

    def __repr__(self) -> str:
        if self.is_infinity():
            return "Point(O)"
        return f"Point({self.x!r}, {self.y!r})"


def _render_point(obj: Point, verbosity: int) -> str:
    if obj.is_infinity():
        return "O (point at infinity)"
    on_curve = "on-curve" if obj.is_on_curve() else "OFF-CURVE!"
    x_r = trace.render(obj.x, verbosity)
    y_r = trace.render(obj.y, verbosity)
    return f"({x_r}, {y_r}) [{on_curve}]"


trace.register_renderer("Point", _render_point)
