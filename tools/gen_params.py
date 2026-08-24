"""Searches for curve parameters satisfying IA-02, and freezes them as IA-07 literals.

E: y^2 = x^3 + x over F_p_field, p_field = 3 (mod 4) => #E(F_p_field) = p_field + 1.
Requires p_field + 1 = r_group * cofactor with r_group prime (a large-enough subgroup order).

Run standalone: `python tools/gen_params.py`. Output is pasted into maka/params.py (IA-07);
this script is not imported at runtime.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from maka.curve import CurveParams, Point  # noqa: E402
from maka.field import Fp  # noqa: E402


def isprime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin. Pure Python -- IA-01 forbids third-party crypto deps in the core, and
    this tool is not imported at runtime, but keeping it dependency-free avoids the question."""
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n == small:
            return True
        if n % small == 0:
            return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    rng = random.Random(n)  # deterministic per-n, fine for a param-search tool
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def nextprime(n: int) -> int:
    candidate = n + 1 if n % 2 == 0 else n + 2
    while not isprime(candidate):
        candidate += 2
    return candidate


def find_params(p_bits: int, r_bits: int, label: str) -> CurveParams:
    p_field = nextprime(1 << (p_bits - 1))
    while p_field.bit_length() == p_bits:
        if p_field % 4 == 3:
            order = p_field + 1
            # search small cofactors so r_group stays close to r_bits
            for cofactor in range(2, 4096, 2):
                if order % cofactor == 0:
                    r_group = order // cofactor
                    if isprime(r_group) and r_group.bit_length() >= r_bits:
                        params = CurveParams(p_field=int(p_field), a=1, b=0, order=int(order),
                                              r_group=int(r_group), cofactor=int(cofactor))
                        g = _find_generator(params)
                        if g is not None:
                            print(f"# {label}: p_field={p_field} ({p_field.bit_length()} bits), "
                                  f"r_group={r_group} ({r_group.bit_length()} bits), cofactor={cofactor}")
                            print(f"# g = ({g.x.val}, {g.y.val})")
                            return params
        p_field = nextprime(p_field)
    raise RuntimeError(f"no suitable p_field found near {p_bits} bits for {label}")


def _find_generator(params: CurveParams) -> Point | None:
    for x_val in range(1, 2000):
        x = Fp(x_val, params.p_field)
        rhs = x * x * x + x
        if rhs.legendre() != 1:
            continue
        y = rhs.sqrt()
        candidate = Point(x, y, params)
        if not candidate.is_on_curve():
            continue
        g = params.cofactor * candidate
        if not g.is_infinity() and (params.r_group * g).is_infinity():
            return g
    return None


if __name__ == "__main__":
    for label, p_bits, r_bits in (("toy", 32, 24), ("demo", 256, 160), ("secure", 512, 160)):
        find_params(p_bits, r_bits, label)
