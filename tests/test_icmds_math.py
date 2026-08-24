"""SD-01 coefficient agreement checks; ER-04 identity comparison."""

from __future__ import annotations

from icmds.coefficients import compute_and_verify, evaluate_polynomial, expand_polynomial
from icmds.session_key import synthetic_er04_demo
from maka import params, rng, trace


def test_polynomial_roots_evaluate_to_zero() -> None:
    r_group = params.get("toy").curve.r_group
    roots = [11, 13, 17]
    coeffs = expand_polynomial(roots, r_group)
    for root in roots:
        assert evaluate_polynomial(coeffs, root, r_group) == 0


def test_coefficients_match_closed_forms() -> None:
    rng.seed(1)
    trace.init(run_id="test-icmds-coeff", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    r_group = params.get("toy").curve.r_group
    roots = [rng.current().below(r_group) or 1 for _ in range(4)]
    coeffs = compute_and_verify(roots, r_group)
    assert coeffs[-1] == 1  # a_m == 1
    for root in roots:
        assert evaluate_polynomial(coeffs, root, r_group) == 0


def test_er04_rp9_rendering_fails_icmds_p_rendering_holds() -> None:
    rng.seed(2)
    trace.init(run_id="test-er04", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)
    p = params.get("toy")
    rp9_holds, icmds_holds = synthetic_er04_demo(p.curve, p.g)
    assert icmds_holds is True
    assert rp9_holds is False
