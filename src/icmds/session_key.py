"""ICMDS RP9 §3 step 5(a)-(d): setup, encryption setup, encryption, decryption.

Applies: SD-01/IA-10 (coefficient computation), ER-04 (decryption identity exponent),
AM-09/IA-11 (x_i's unresolved G_2 -> scalar type, two-track handling), OB-06 (R point/scalar
collision), ER-05 (S_ID selection actor, demonstrated in attacks/icmds/a7_sk_impossible.py).

ICMDS-P's `p` (order of G1, G2) resolves to r_group throughout, per IA-02's domain-naming
table -- never p_field.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from icmds.coefficients import compute_and_verify
from maka import hashing, pairing, trace
from maka.curve import CurveParams, Point
from maka.field import Fp2, fp2_to_bytes


@dataclass
class SetupParams:
    s: int  # master secret, Z_r_group
    g: Point  # generator (RP9/ICMDS-P write "P"; we reuse the curve generator g)
    p_pub: Point  # s*P


def setup(curve: CurveParams, g: Point, s_scalar: int) -> SetupParams:
    """RP9 §3 step 5(a): (p_field... [unused symbol q not resolved, see AM-08 scope]),
    G1, G2, s, P, P_pub = sP, H1, H2, Q_ID = H1(ID), S_ID = s*Q_ID."""
    t = trace.active()
    p_pub = s_scalar * g
    t.register("ER-05", "RP9's §3 summary states the BS selects s (step 5(a)); ICMDS-P's "
                         "explicit system-setup sentence instead states the cluster head "
                         "selects it. Implemented per RP9's summary, since RP9 is the paper "
                         "being reproduced -- see attacks/icmds/a7_sk_impossible.py for the "
                         "full side-by-side comparison.")
    t.value("P_pub = s*P", p_pub)
    return SetupParams(s=s_scalar, g=g, p_pub=p_pub)


def gateway_key(curve: CurveParams, params: SetupParams, node_id: str) -> tuple[Point, Point]:
    """Q_ID = H1(ID), S_ID = s*Q_ID -- ICMDS-P §3(1): 'each gateway sets S_ID = sQ_ID'."""
    t = trace.active()
    q_id = hashing.hash_to_point(curve, node_id.encode(), domain=b"ICMDS-H1")
    s_id = params.s * q_id
    t.formula(f"Q_{node_id}", "H1(ID)", q_id)
    t.formula(f"S_{node_id}", "s * Q_ID", s_id)
    return q_id, s_id


@dataclass
class EncryptionSetup:
    r: int
    r_point: Point  # R = r*P
    x_values: dict[str, Fp2]  # x_i = e(r*Q_IDi, P_pub) per recipient -- AM-09
    coeff_points: list[Point]  # {a_0*P, ..., a_m*P}, from SD-01/IA-10


def encryption_setup(curve: CurveParams, params: SetupParams, r_scalar: int,
                      recipient_q_ids: dict[str, Point], roots_r_group: list[int]) -> EncryptionSetup:
    """RP9 §3 step 5(b): r, R = rP, x_i = e(rQ_IDi, P_pub), {a_0..a_m} -> {P_0..P_m}."""
    t = trace.active()
    r_point = r_scalar * params.g
    t.formula("R (encryption-setup point)", "r * P", r_point)

    x_values = {}
    for node_id, q_id in recipient_q_ids.items():
        x_i = pairing.modified_pairing(curve, r_scalar * q_id, params.p_pub)
        t.register("AM-09", f"x_{node_id} = e(rQ_ID, P_pub) is a G_2 element (both F_p2 "
                              f"components below), but is later required to act as a scalar "
                              f"root of f(x) mod r_group and as x_i^j multiplying a G1 point. "
                              f"Neither source specifies a G_2 -> scalar map.")
        t.value(f"x_{node_id}", x_i, note="[AM-09] G_2 element -- see IA-11 for the two-track handling")
        x_values[node_id] = x_i

    coeffs = compute_and_verify(roots_r_group, curve.r_group)
    coeff_points = [a_j * params.g for a_j in coeffs]
    t.value("{a_0*P .. a_m*P}", coeff_points)

    return EncryptionSetup(r=r_scalar, r_point=r_point, x_values=x_values, coeff_points=coeff_points)


def to_scalar(g2_element: Fp2, r_group: int) -> int:
    """IA-11 Track B: a declared conversion G_2 -> Z_r_group, used ONLY as a diagnostic
    continuation -- never described as the literal protocol. Not specified or justified by
    either source; not claimed to preserve any structure beyond deterministic equality."""
    encoded = b"ICMDS-AM09" + fp2_to_bytes(g2_element)
    return int.from_bytes(hashlib.sha256(encoded).digest(), "big") % r_group


@dataclass
class Ciphertext:
    r_broadcast: Point  # the tuple's "R" field (the point from encryption setup)
    c: bytes  # S_k xor H2(D)
    c_0: Point
    c_rest: list[Point]


def encrypt_literal(curve: CurveParams, enc_setup: EncryptionSetup, s_k: bytes, d_point: Point) -> Ciphertext:
    """RP9 §3 step 5(c) / ICMDS-P §3(2)(b): 'Select R in Z and D in G1 two random numbers'
    and broadcast T = (R, C, C_0..C_m) with C_0 = D + R*P_0.

    OB-06: ICMDS-P's own text uses the symbol R for both the POINT R = rP computed in
    encryption setup and a freshly selected SCALAR consumed here. We do not invent a
    resolution by picking whichever meaning makes the code run: we reuse the single R value
    already produced (a Point) at both the point-role (broadcast tuple field, needed later by
    decryption's e(S_IDi, R)) and the scalar-role RP9's own text assigns it here. Executed
    literally, R*P_0 asks a Point to scalar-multiply a Point, which is not an operation our
    type system defines -- Python's TypeError is the halt, not a scripted failure point.
    """
    t = trace.active()
    t.register("OB-06", "ICMDS-P computes R = rP (a point) in encryption setup, then in "
                         "encryption says 'Select R in Z and D in G1 two random numbers' and "
                         "broadcasts T=(R,C,C_0..C_m) with C_0 = D + R*P_0. The single symbol "
                         "R denotes both a point and a scalar. Executed literally below.")
    h2d = hashing.h2_point_to_bytes(d_point, nbytes=len(s_k))
    c = bytes(a ^ b for a, b in zip(s_k, h2d))
    r_reused = enc_setup.r_point  # the only "R" this module has produced (a Point)
    c_0 = d_point + (r_reused * enc_setup.coeff_points[0])  # type: ignore[operator]  -- deliberately literal
    c_rest = [r_reused * p_j for p_j in enc_setup.coeff_points[1:]]  # type: ignore[operator]
    return Ciphertext(r_broadcast=r_reused, c=c, c_0=c_0, c_rest=c_rest)


def synthetic_er04_demo(curve: CurveParams, g: Point) -> tuple[bool, bool]:
    """SD-01/ER-04, on synthetic data: roots and R drawn directly as scalars in Z_r_group (not
    via AM-09's conversion -- see IA-10), so the polynomial identity is verified independently
    of AM-09/IA-11. Builds C_0, C_1..C_m and D from scratch so the identity is checked against
    ground truth, not against the OB-06-colliding broadcast path."""
    from maka import rng

    r_group = curve.r_group
    roots = [rng.current().below(r_group) or 1 for _ in range(3)]
    coeffs = compute_and_verify(roots, r_group)
    points = [a_j * g for a_j in coeffs]

    r_scalar = rng.current().below(r_group) or 1
    d_point = rng.current().below(r_group) * g

    c_0 = d_point + r_scalar * points[0]
    c_rest = [r_scalar * p_j for p_j in points[1:]]

    x_i = roots[0]  # a genuine root of f, as ICMDS-P's decryption requires
    return decrypt_identity_er04(curve, coeffs, x_i, c_0, c_rest, d_point)


def decrypt_identity_er04(curve: CurveParams, coeffs: list[int], x_i: int, c_0: Point,
                           c_rest: list[Point], d_expected: Point) -> tuple[bool, bool]:
    """ER-04: RP9 renders the decryption identity as C_0 + sum x_i*C_j = D. ICMDS-P eq. (17)
    has C_0 + sum x_i^j * C_j = D (the exponent). Returns (rp9_literal_holds, icmds_p_holds).
    """
    t = trace.active()
    r_group = curve.r_group
    rp9_sum = c_0
    for c_j in c_rest:
        rp9_sum = rp9_sum + (x_i % r_group) * c_j
    rp9_holds = rp9_sum == d_expected

    icmds_sum = c_0
    for j, c_j in enumerate(c_rest, start=1):
        icmds_sum = icmds_sum + pow(x_i, j, r_group) * c_j
    icmds_holds = icmds_sum == d_expected

    t.register("ER-04", "RP9 §3 step 5(d) renders C_0 + sum x_i*C_j = D (no exponent); "
                         "ICMDS-P eq. (17) has C_0 + sum x_i^j*C_j = D. The exponent is lost "
                         "in RP9's transcription.")
    t.check("RP9's rendering (no exponent) satisfies the identity", rp9_holds, True, rp9_holds)
    t.check("ICMDS-P's rendering (with exponent) satisfies the identity", icmds_holds, True, icmds_holds)
    return rp9_holds, icmds_holds
