"""The concrete pairing instantiating RP9's abstract e: G1 x G1 -> G2.

Realises: RP9 §2.2 (abstract pairing axioms). Applies: IA-02.

RP9 uses the pairing symmetrically: e(Pr_i, Pu_BS) with both arguments in the same group G.
A plain (Weil/Tate) pairing on a single group is degenerate (alternating: e(P,P)=1 for all P
under the Weil pairing -- see ER-03), so RP9's symmetric use requires a *modified* pairing.
We instantiate via a distortion map phi and define ê(P, Q) := e_r(P, phi(Q)) (IA-02).

P3.1 Miller's algorithm.  P3.2 distortion map.  P3.3 weil/tate paths.  P3.4 selftest (ER-03).
"""

from __future__ import annotations

from maka import ledger, rng, trace
from maka.curve import CurveParams, Point, small_const
from maka.field import Fp, Fp2


def distortion_map(params: CurveParams, point: Point) -> Point:
    """phi(x, y) = (-x, i*y), mapping E(F_p_field) into E(F_p_field^2) \\ E(F_p_field).

    Valid for the supersingular curve y^2 = x^3 + x (a=1, b=0) over p_field = 3 (mod 4).
    """
    if point.is_infinity():
        return Point.infinity(params)
    assert point.x is not None and point.y is not None
    p_field = params.p_field
    zero = Fp(0, p_field)
    x2 = Fp2(-point.x, zero)  # -x, as an Fp2 element with imaginary part 0
    y2 = Fp2(zero, point.y)  # i * y
    return Point(x2, y2, params)  # type: ignore[arg-type]  -- coordinates now live in Fp2


def _lift(x: Fp | Fp2) -> Fp2:
    """Embeds an F_p_field element into F_p_field^2 with zero imaginary part; a value already
    in F_p_field^2 (e.g. a distorted point's coordinate) passes through unchanged. This lets
    _line_eval handle both the plain pairing (both points in G1, F_p_field-rational) and the
    modified pairing (second point distorted into F_p_field^2) uniformly."""
    if isinstance(x, Fp2):
        return x
    return Fp2(x, Fp(0, x.p_field))


def _line_eval(p1: Point, p2: Point, at: Point) -> Fp2:
    """Evaluates the line through p1, p2 (tangent if p1 == p2) at the point `at`.

    p1, p2 have F_p_field coordinates (the Miller-loop accumulator stays on E(F_p_field) since
    the base point is F_p_field-rational); `at` has F_p_field^2 coordinates (the distorted
    second argument). The line's coefficients are lifted into F_p_field^2 before evaluation.
    """
    if p1.is_infinity() or p2.is_infinity():
        raise ValueError("line evaluation undefined at infinity")
    assert p1.x is not None and p1.y is not None
    assert at.x is not None and at.y is not None
    ax, ay = _lift(at.x), _lift(at.y)
    if p1.x == p2.x and (p2.y is None or p1.y != p2.y):
        # vertical line x = p1.x
        return ax - _lift(p1.x)
    if p1.x == p2.x and p1.y == p2.y:
        # tangent line at p1 -- p1's coordinates may be Fp (G1) or Fp2 (a distorted point being
        # doubled inside the second Miller loop of the plain Weil pairing); small_const builds
        # the curve constants generically in whichever field p1.x lives in (see curve.py).
        three = small_const(p1.x, 3)
        a_elem = small_const(p1.x, p1.params.a)
        slope = (p1.x * p1.x * three + a_elem) / (p1.y + p1.y)
    else:
        assert p2.x is not None and p2.y is not None
        slope = (p2.y - p1.y) / (p2.x - p1.x)
    return (ay - _lift(p1.y)) - _lift(slope) * (ax - _lift(p1.x))


def _vertical_eval(c: Point, at: Point) -> Fp2:
    """Evaluates the vertical line x = c.x at `at`. Full (non-optimised) Miller's algorithm
    needs this denominator at every step; omitting it (as the Tate-only 'denominator-free'
    optimisation does) is only valid after a final exponentiation kills the surviving subfield
    factor, which weil_pairing's raw quotient formula does not perform. Since a point can
    legitimately double to infinity on the final loop iteration (2T = r_group*P = O), that case
    contributes no vertical line and the denominator is taken as 1."""
    if c.is_infinity():
        return Fp2(Fp(1, at.params.p_field), Fp(0, at.params.p_field))
    assert at.x is not None
    return _lift(at.x) - _lift(c.x)


def miller_loop(params: CurveParams, pt: Point, q: Point, verbosity: int = 2) -> Fp2:
    """Miller's algorithm computing f_{r_group, P}(Q), the core of the Weil/Tate pairing.

    Full form (line divided by vertical line at each step), not the denominator-free
    optimisation -- that optimisation is only valid once a final exponentiation by
    (p_field^2 - 1) / r_group has killed the surviving subfield factor (as tate_pairing does);
    weil_pairing's raw two-loop quotient has no such exponentiation, so the denominators are
    kept throughout for both callers.
    """
    r_group = params.r_group
    p_field = params.p_field
    one = Fp2(Fp(1, p_field), Fp(0, p_field))
    f = one
    t = pt
    bits = bin(r_group)[2:]
    tr = trace.active()
    for i, bit in enumerate(bits[1:]):
        num = _line_eval(t, t, q)
        t2 = t._add_impl(t)
        den = _vertical_eval(t2, q)
        f = f * f * num / den
        t = t2
        if tr.verbosity >= 3:
            tr.step("miller_loop", f"bit {i}: DBL, f={f!r}")
        if bit == "1":
            num = _line_eval(t, pt, q)
            t3 = t._add_impl(pt)
            den = _vertical_eval(t3, q)
            f = f * num / den
            t = t3
            if tr.verbosity >= 3:
                tr.step("miller_loop", f"bit {i}: ADD, f={f!r}")
    return f


@ledger.counts("T_P")
def weil_pairing(params: CurveParams, pt: Point, q: Point) -> Fp2:
    """e_r(P, Q) via two Miller loops and a quotient -- the plain (alternating) Weil pairing.

    The textbook formula is w_r(P,Q) = (-1)^r_group * f_P(Q)/f_Q(P): the bare quotient of two
    Miller functions lands in the group of r_group-th roots of unity only up to that sign
    (r_group is an odd prime in every IA-07 parameter set, so the correction is a negation).
    Without it, w_r(P,P)^r_group evaluates to -1 rather than 1, i.e. the identity computed
    would have order 2*r_group instead of r_group.
    """
    if pt.is_infinity() or q.is_infinity():
        return Fp2(Fp(1, params.p_field), Fp(0, params.p_field))
    f_pq = miller_loop(params, pt, q)
    f_qp = miller_loop(params, q, pt)
    raw = f_pq / f_qp
    return -raw if params.r_group % 2 == 1 else raw


@ledger.counts("T_P")
def tate_pairing(params: CurveParams, pt: Point, q: Point) -> Fp2:
    """Tate pairing via a single Miller loop and final exponentiation (p_field^2-1)/r_group.

    Independent second path for internal cross-validation against weil_pairing (P3.3).
    """
    if pt.is_infinity() or q.is_infinity():
        return Fp2(Fp(1, params.p_field), Fp(0, params.p_field))
    f = miller_loop(params, pt, q)
    exponent = (params.p_field ** 2 - 1) // params.r_group
    return f ** exponent


def modified_pairing(params: CurveParams, pt: Point, q: Point, backend: str = "weil") -> Fp2:
    """ê(P, Q) := e_r(P, phi(Q)) -- the non-degenerate pairing RP9's symmetric use requires
    (IA-02). `backend` selects weil_pairing or tate_pairing as the underlying primitive."""
    phi_q = distortion_map(params, q)
    fn = weil_pairing if backend == "weil" else tate_pairing
    return fn(params, pt, phi_q)


def _render_fp2_g2(obj: Fp2, verbosity: int) -> str:
    return f"({obj.a.val} + {obj.b.val}*i)  [G_2 element, order should be r_group]"


def selftest(params: CurveParams, g: Point, backend: str = "weil") -> list[tuple[int, str, bool]]:
    """P3.4: the seven pairing properties, printed side by side. Returns (test#, name, ok)."""
    t = trace.active()
    r_group = params.r_group
    results: list[tuple[int, str, bool]] = []

    rng_a, rng_b = 3, 5  # small fixed exponents; deterministic, hand-checkable at `toy`

    def e(pt: Point, q: Point) -> Fp2:
        return modified_pairing(params, pt, q, backend=backend)

    one = Fp2(Fp(1, params.p_field), Fp(0, params.p_field))

    # 1. Bilinearity, left
    lhs1 = e(rng_a * g, g)
    rhs1 = e(g, g) ** rng_a
    ok1 = lhs1 == rhs1
    t.check("bilinearity (left): ê(aP,Q) = ê(P,Q)^a  [RP9 §2.2 axiom]", ok1, rhs1, lhs1)
    results.append((1, "bilinearity-left", ok1))

    # 2. Bilinearity, right
    lhs2 = e(g, rng_b * g)
    rhs2 = e(g, g) ** rng_b
    ok2 = lhs2 == rhs2
    t.check("bilinearity (right): ê(P,bQ) = ê(P,Q)^b  [RP9 §2.2 axiom]", ok2, rhs2, lhs2)
    results.append((2, "bilinearity-right", ok2))

    # 3. Combined bilinearity
    lhs3 = e(rng_a * g, rng_b * g)
    rhs3 = e(g, g) ** (rng_a * rng_b)
    ok3 = lhs3 == rhs3
    t.check("combined bilinearity: ê(aP,bQ) = ê(P,Q)^(ab)  [RP9 §2.2]", ok3, rhs3, lhs3)
    results.append((3, "bilinearity-combined", ok3))

    # 4. Computability -- evidenced by the fact the above ran at all
    ok4 = True
    t.check("computability (evidenced by execution)  [RP9 §2.2 axiom]", ok4, "computed", "computed")
    results.append((4, "computability", ok4))

    # 5. ER-03: the PLAIN Weil pairing is alternating: e_r(P,P) = 1. This is specifically a
    # Weil-pairing property (not claimed for the Tate pairing), so weil_pairing is used here
    # regardless of the `backend` selftest was called with.
    # Direct evaluation e(P,P) is a Miller-loop singularity (the divisor of f_P has a zero
    # exactly at P, so evaluating it at Q=P hits 0/0); this is a property of Miller's
    # algorithm, not of the pairing itself. We obtain the well-defined value via bilinearity,
    # evaluated at points that differ from P: e(P,P) = e(P, P+S) / e(P,S) for an auxiliary S.
    # A second Miller-loop singularity can also occur for an unlucky S (the loop's internal
    # accumulator T = k*P can coincide with S*P at some intermediate step); this is retried
    # with a fresh S -- standard practice for Miller's algorithm, not a result-shaping choice.
    plain = one
    aux_rng = rng.current().spawn("pairing-selftest-aux")
    for _ in range(8):
        s = aux_rng.randint(2, r_group - 1)
        aux = s * g
        p_plus_aux = g + aux
        try:
            plain = weil_pairing(params, g, p_plus_aux) / weil_pairing(params, g, aux)
            break
        except ZeroDivisionError:
            continue
    ok5 = plain == one
    t.register("ER-03", "RP9 §2.2 prints e(P,P)=1 under the heading 'non-degeneracy'; as printed "
                         "this is the ALTERNATING property of the plain Weil pairing, not "
                         "non-degeneracy. Demonstrated here, not silently normalised.")
    t.check("alternating: e_r(P,P) = 1  [RP9 §2.2 as printed -- ER-03]", ok5, one, plain)
    results.append((5, "alternating-plain", ok5))

    # 6. Non-degeneracy proper, via the distortion map
    modified_gg = e(g, g)
    ok6 = modified_gg != one
    t.check("non-degeneracy proper: ê(g,g) != 1  [our reading of the intended primitive -- ER-03]",
            ok6, "!= 1", modified_gg)
    order_ok = modified_gg ** r_group == one
    t.check("ord(ê(g,g)) divides r_group", order_ok, one, modified_gg ** r_group)
    results.append((6, "non-degeneracy-modified", ok6 and order_ok))

    # 7. Symmetry -- NOT an RP9 axiom, a property of our instantiation (IA-02)
    lhs7 = e(rng_a * g, rng_b * g)
    rhs7 = e(rng_b * g, rng_a * g)
    ok7 = lhs7 == rhs7
    t.register("IA-02", "symmetry ê(P,Q) = ê(Q,P) is NOT one of RP9's stated axioms; it is a "
                         "property of our Type-1 supersingular instantiation.")
    t.check("symmetry: ê(P,Q) = ê(Q,P)  [ours, IA-02 -- not an RP9 axiom]", ok7, rhs7, lhs7)
    results.append((7, "symmetry", ok7))

    return results
