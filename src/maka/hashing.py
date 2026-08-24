"""Hash constructions -- two distinct kinds (IA-09).

RP9 gives H : {0,1}* -> G (MAKA) and ICMDS gives H1 : {0,1}* -> G1, H2 : G1 -> {0,1}*.
H / H1 hash *to* a point (try-and-increment); H2 hashes *of* a point (canonical
serialisation then SHA-256). These are opposite-direction functions and must not share an
implementation -- enforced by tests/test_primitives.py.
"""

from __future__ import annotations

import hashlib

from maka import ledger, trace
from maka.curve import CurveParams, Point
from maka.field import Fp


@ledger.counts("T_HG")
def hash_to_point(params: CurveParams, data: bytes, domain: bytes = b"MAKA-H") -> Point:
    """Try-and-increment: hash counter||domain||data to a candidate x, test quadratic
    residuosity, take the root, clear the cofactor into the order-r_group subgroup."""
    t = trace.active()
    counter = 0
    while True:
        digest = hashlib.sha256(counter.to_bytes(4, "big") + domain + data).digest()
        x_val = int.from_bytes(digest, "big") % params.p_field
        x = Fp(x_val, params.p_field)
        rhs = x * x * x + Fp(params.a, params.p_field) * x + Fp(params.b, params.p_field)
        if t.verbosity >= 3:
            t.step("hash_to_point", f"trial {counter}: x={x_val}, QR={rhs.legendre()}")
        if rhs.legendre() == 1:
            y = rhs.sqrt()
            candidate = Point(x, y, params)
            assert candidate.is_on_curve()
            point = candidate.scalar_mul_unaccounted(params.cofactor)
            if not point.is_infinity():
                if t.verbosity >= 2:
                    t.value("hash_to_point.result", point,
                            note=f"accepted at trial {counter}, cofactor-cleared")
                return point
        counter += 1


def h2_point_to_bytes(point: Point, nbytes: int, domain: bytes = b"MAKA-H2") -> bytes:
    """ICMDS's H2 : G1 -> {0,1}*. Canonical fixed-width serialisation of the affine point
    (both coordinates, big-endian, length-prefixed), then SHA-256, truncated/expanded to
    `nbytes` (matching |S_k|, per IA-09)."""
    if point.is_infinity():
        raise ValueError("H2 undefined at the point at infinity")
    assert point.x is not None and point.y is not None
    p_bytes = (point.params.p_field.bit_length() + 7) // 8
    encoded = point.x.val.to_bytes(p_bytes, "big") + point.y.val.to_bytes(p_bytes, "big")
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        out.extend(hashlib.sha256(domain + counter.to_bytes(4, "big") + encoded).digest())
        counter += 1
    return bytes(out[:nbytes])


def kdf(gt_repr: bytes, label: bytes, nbytes: int) -> bytes:
    """Derives symmetric key material from a G_2 (pairing target) element's canonical bytes."""
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        out.extend(hashlib.sha256(b"MAKA-KDF" + label + counter.to_bytes(4, "big") + gt_repr).digest())
        counter += 1
    return bytes(out[:nbytes])
