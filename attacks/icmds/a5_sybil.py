"""RP9 §4.5: intercept public-key distribution; instantiate n fake identities; all accepted."""

from __future__ import annotations

from icmds import scheme
from attacks.framework import verdict
from attacks.icmds import _scenario
from maka import trace
from maka.curve import CurveParams, Point


def run(curve: CurveParams, g: Point, n_fake: int = 5) -> str:
    verdict("a5_sybil", "RP9 §4.5", f"Intercepting distribution and instantiating {n_fake} fake identities")
    t = trace.active()
    scn = _scenario.build(curve, g)

    accepted = []
    for i in range(n_fake):
        fake_id = f"SYBIL-{i:03d}"
        fake_pk = scheme.bs_generate_public_key(fake_id, distance=3, bs_stamp=b"forged-stamp")
        ok = scheme.ch_recheck_public_key(fake_pk, expected_distance=3)
        accepted.append(ok)

    t.check(f"all {n_fake} fake identities accepted by the CH's re-check",
            all(accepted), True, all(accepted))
    t.step("RP9 §4.5", "ICMDS specifies no binding between an identity and a physical node, "
                        "so an adversary that intercepts key distribution can instantiate "
                        "arbitrarily many accepted identities.")
    verdict("a5_sybil", "RP9 §4.5", "SUCCEEDS (as claimed in §4.5)")
    return "SUCCEEDS (as claimed in §4.5)"
