"""Prime-field and quadratic-extension-field arithmetic.

Realises: RP9 §2.1-2.2 preliminaries (abstract), instantiated per IA-02.
Applies: IA-02 (Type-1 supersingular pairing instantiation).

P2.1: Fp -- add/sub/mul/inverse (extended Euclid), sqrt for p_field = 3 (mod 4), legendre.
P2.2: Fp2 = Fp[i]/(i^2 + 1) -- arithmetic, Frobenius, norm.

Domain naming (IA-02): the modulus here is always `p_field`, the curve base-field modulus.
It is never called a bare `p` -- see the IA-02 domain-naming table in PLAN.md and the
`r_group` (subgroup order) used by maka.curve / maka.pairing / icmds.
"""

from __future__ import annotations

from dataclasses import dataclass

from maka import trace


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Returns (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


@dataclass(frozen=True)
class Fp:
    """An element of Z/p_field Z, the curve base field."""

    val: int
    p_field: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "val", self.val % self.p_field)

    def _check_field(self, other: "Fp") -> None:
        if self.p_field != other.p_field:
            raise ValueError("operands drawn from different fields (mismatched p_field)")

    def __add__(self, other: "Fp") -> "Fp":
        self._check_field(other)
        return Fp((self.val + other.val) % self.p_field, self.p_field)

    def __sub__(self, other: "Fp") -> "Fp":
        self._check_field(other)
        return Fp((self.val - other.val) % self.p_field, self.p_field)

    def __neg__(self) -> "Fp":
        return Fp((-self.val) % self.p_field, self.p_field)

    def __mul__(self, other: "Fp") -> "Fp":
        self._check_field(other)
        return Fp((self.val * other.val) % self.p_field, self.p_field)

    def __pow__(self, e: int) -> "Fp":
        return Fp(pow(self.val, e, self.p_field), self.p_field)

    def inverse(self) -> "Fp":
        if self.val == 0:
            raise ZeroDivisionError("no inverse of 0 in Fp")
        g, x, _ = extended_gcd(self.val, self.p_field)
        assert g == 1
        return Fp(x % self.p_field, self.p_field)

    def __truediv__(self, other: "Fp") -> "Fp":
        return self * other.inverse()

    def is_zero(self) -> bool:
        return self.val == 0

    def legendre(self) -> int:
        """Legendre symbol (val / p_field): 1 if QR, -1 if non-residue, 0 if val == 0."""
        if self.val == 0:
            return 0
        r = pow(self.val, (self.p_field - 1) // 2, self.p_field)
        return -1 if r == self.p_field - 1 else r

    def sqrt(self) -> "Fp":
        """Square root, requiring p_field = 3 (mod 4) (guaranteed by IA-02's curve choice)."""
        if self.p_field % 4 != 3:
            raise ValueError("sqrt() requires p_field = 3 (mod 4); see IA-02")
        if self.legendre() != 1:
            raise ValueError("value is not a quadratic residue mod p_field")
        root = pow(self.val, (self.p_field + 1) // 4, self.p_field)
        return Fp(root, self.p_field)

    def __repr__(self) -> str:
        return f"Fp({self.val}, p_field={self.p_field})"


def _render_fp(obj: Fp, verbosity: int) -> str:
    return f"{obj.val} (0x{obj.val:x})" if verbosity >= 2 else str(obj.val)


trace.register_renderer("Fp", _render_fp)


@dataclass(frozen=True)
class Fp2:
    """An element a + b*i of F_p_field[i] / (i^2 + 1), used as the pairing target field
    (IA-02: embedding degree k=2)."""

    a: Fp
    b: Fp

    def _check_field(self, other: "Fp2") -> None:
        if self.a.p_field != other.a.p_field:
            raise ValueError("operands drawn from different fields (mismatched p_field)")

    def __add__(self, other: "Fp2") -> "Fp2":
        self._check_field(other)
        return Fp2(self.a + other.a, self.b + other.b)

    def __sub__(self, other: "Fp2") -> "Fp2":
        self._check_field(other)
        return Fp2(self.a - other.a, self.b - other.b)

    def __neg__(self) -> "Fp2":
        return Fp2(-self.a, -self.b)

    def __mul__(self, other: "Fp2") -> "Fp2":
        self._check_field(other)
        # (a + bi)(c + di) = (ac - bd) + (ad + bc)i, since i^2 = -1
        a, b, c, d = self.a, self.b, other.a, other.b
        return Fp2(a * c - b * d, a * d + b * c)

    def __pow__(self, e: int) -> "Fp2":
        if e < 0:
            return self.inverse() ** (-e)
        result = Fp2(Fp(1, self.a.p_field), Fp(0, self.a.p_field))
        base = self
        while e > 0:
            if e & 1:
                result = result * base
            base = base * base
            e >>= 1
        return result

    def conjugate(self) -> "Fp2":
        """The Frobenius map x -> x^p_field, which on Fp2 = Fp[i] is (a+bi) -> (a-bi)."""
        return Fp2(self.a, -self.b)

    def norm(self) -> Fp:
        """N(a+bi) = (a+bi)(a-bi) = a^2 + b^2, an element of the base field Fp."""
        prod = self * self.conjugate()
        assert prod.b.is_zero()
        return prod.a

    def inverse(self) -> "Fp2":
        # (a+bi)^-1 = (a-bi) / N(a+bi)
        n = self.norm()
        conj = self.conjugate()
        n_inv = n.inverse()
        return Fp2(conj.a * n_inv, conj.b * n_inv)

    def __truediv__(self, other: "Fp2") -> "Fp2":
        return self * other.inverse()

    def is_zero(self) -> bool:
        return self.a.is_zero() and self.b.is_zero()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Fp2):
            return NotImplemented
        return self.a == other.a and self.b == other.b

    def __repr__(self) -> str:
        return f"Fp2({self.a.val} + {self.b.val}*i)"


def _render_fp2(obj: Fp2, verbosity: int) -> str:
    return f"({obj.a.val} + {obj.b.val}*i)"


trace.register_renderer("Fp2", _render_fp2)
