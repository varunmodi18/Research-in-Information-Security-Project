"""ICMDS coefficient computation (SD-01 / IA-10).

ICMDS-P gives closed forms only for a_0, a_1, a_{m-2}, a_{m-1}, a_m -- not a general formula
for arbitrary a_k -- and its eq. (11) for a_1 reuses `j` as both the outer summation index
and the inner exclusion index, which cannot be read literally. We obtain all coefficients by
direct polynomial expansion of f(x) = prod_{i=1}^m (x - x_i) mod r_group, which requires no
closed form and reproduces every one ICMDS-P does state.

ICMDS-P's `p` (order of G1, G2) resolves to r_group throughout this module, per IA-02's
domain-naming table -- never p_field.
"""

from __future__ import annotations

from maka import trace


def expand_polynomial(roots: list[int], r_group: int) -> list[int]:
    """f(x) = prod (x - x_i) mod r_group, returned as [a_0, a_1, ..., a_m] (a_m = 1)."""
    coeffs = [1]  # f(x) = 1 initially (degree 0)
    for root in roots:
        # multiply current poly by (x - root): new_coeffs[k] = coeffs[k-1] - root*coeffs[k]
        new_coeffs = [0] * (len(coeffs) + 1)
        for k, c in enumerate(coeffs):
            new_coeffs[k + 1] = (new_coeffs[k + 1] + c) % r_group
            new_coeffs[k] = (new_coeffs[k] - root * c) % r_group
        coeffs = new_coeffs
    return coeffs


def evaluate_polynomial(coeffs: list[int], x: int, r_group: int) -> int:
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % r_group
    return result


def compute_and_verify(roots: list[int], r_group: int) -> list[int]:
    """SD-01: computes a_0..a_m by expansion, then checks every ICMDS-P closed form it states
    and that f(x_i) = 0 for every root (the identity the decryption step depends on)."""
    t = trace.active()
    m = len(roots)
    t.register("SD-01", "RP9 §3 step 5(b): 'The calculation of a_0, a_1, ..., a_m is provided "
                         "in detail in [26]' -- resolved from ICMDS-P §3(2)(a), eqs. (10)-(14). "
                         "Computed here by direct polynomial expansion (IA-10), which requires "
                         "no closed form and is checked against every one ICMDS-P states.")
    coeffs = expand_polynomial(roots, r_group)
    t.value("f(x) coefficients [a_0..a_m]", coeffs)

    # closed forms ICMDS-P states
    a_m = coeffs[m]
    t.check("a_m == 1", a_m == 1, 1, a_m)

    a_0 = 1
    for r in roots:
        a_0 = (a_0 * (-r)) % r_group
    t.check("a_0 == prod(-x_j)", coeffs[0] == a_0 % r_group, a_0 % r_group, coeffs[0])

    a_m_minus_1 = sum((-r) % r_group for r in roots) % r_group
    t.check("a_{m-1} == sum(-x_j)", coeffs[m - 1] == a_m_minus_1, a_m_minus_1, coeffs[m - 1])

    if m >= 2:
        a_m_minus_2 = 0
        for i in range(m):
            for j in range(i + 1, m):
                a_m_minus_2 = (a_m_minus_2 + (-roots[i] % r_group) * (-roots[j] % r_group)) % r_group
        t.check("a_{m-2} == sum_{i<j}(-x_i)(-x_j)", coeffs[m - 2] == a_m_minus_2, a_m_minus_2, coeffs[m - 2])

    a_1 = 0
    for i in range(m):
        term = 1
        for j in range(m):
            if j != i:
                term = (term * (-roots[j] % r_group)) % r_group
        a_1 = (a_1 + term) % r_group
    t.check("a_1 == sum_i prod_{j!=i}(-x_j)", coeffs[1] == a_1, a_1, coeffs[1])

    for i, root in enumerate(roots):
        val = evaluate_polynomial(coeffs, root, r_group)
        t.check(f"f(x_{i+1}) == 0 (decryption identity dependency)", val == 0, 0, val)

    return coeffs
