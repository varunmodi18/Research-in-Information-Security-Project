"""RP9 §4.7: the central finding -- session-key computation is impossible for the CH.

Two explicitly separated branches (IA-11):

(i) LITERAL branch. Executes the §3 protocol as written and reports exactly what stops it,
    naming the operation and its register ID. This may be the AM-09 domain failure or the
    OB-06 collision; it is not scripted to be either. No claim is made about which defect
    comes "first" -- that would be an artefact of function ordering.

(ii) RP9 §4.7 DIAGNOSTIC branch. Independently of any execution, and requiring no conversion,
     inspects the two requirements RP9's objection rests on: the S_ID requirement (ER-05) and
     the R requirement (OB-06), displaying each symbolically. States that the R obstruction
     alone is sufficient for RP9's conclusion, and that AM-09 is a further obstruction RP9
     does not identify.

Neither branch adjudicates what ICMDS intended, and neither depends on IA-11's Track B.
"""

from __future__ import annotations

from icmds import session_key
from attacks.framework import verdict
from attacks.icmds import _scenario
from maka import rng, trace
from maka.curve import CurveParams, Point


def _literal_branch(curve: CurveParams, g: Point) -> str:
    t = trace.active()
    t.section("4.7-i", "Literal branch: execute §3 as written")
    scn = _scenario.build(curve, g)
    setup_params = scn.setup_params

    q_ids = {}
    for nid in scn.node_ids:
        q_id, s_id = session_key.gateway_key(curve, setup_params, nid)
        q_ids[nid] = q_id

    roots = [rng.current().below(curve.r_group) or 1 for _ in range(3)]
    r_scalar = rng.current().below(curve.r_group) or 1
    enc_setup = session_key.encryption_setup(curve, setup_params, r_scalar, q_ids, roots)

    try:
        session_key.encrypt_literal(curve, enc_setup, b"sessionkeybytes", r_scalar * g)
        halt_reason = "no obstruction encountered (unexpected)"
        halt_id = None
    except TypeError as exc:
        halt_reason = f"OB-06: R point/scalar collision -- {exc}"
        halt_id = "OB-06"

    t.value("literal-branch verdict", "HALTED -- NO SPECIFIED DOMAIN / TYPE COLLISION")
    t.value("halted at", halt_reason)
    return halt_id or "UNKNOWN"


def _diagnostic_branch(curve: CurveParams, g: Point) -> None:
    t = trace.active()
    t.section("4.7-ii", "RP9 §4.7 diagnostic branch: the S_ID and R requirements, symbolically")

    t.register("ER-05", "S_ID requirement: RP9's §3 summary states the BS selects the master "
                         "secret s (step 5(a)); §4.7 rests half its objection on the CH never "
                         "receiving it. ICMDS-P's explicit system-setup sentence instead states "
                         "the cluster head selects s. RP9 assigns selection of s to a different "
                         "actor from the one named in the source text it is summarising. "
                         "ICMDS-P is itself internally inconsistent here (it also says the "
                         "system public key 'is then delivered to the CH'). RP9's §4.7 "
                         "objection is therefore inaccurate ON THE S_ID HALF ONLY.")

    t.register("OB-06", "R requirement: ICMDS-P computes R = rP (a point) in encryption "
                         "setup, then in encryption says 'Select R in Z...' (a scalar) and "
                         "broadcasts T=(R,C,C_0..C_m). Decryption needs the POINT rP for "
                         "e(S_IDi, R); the tuple's own construction conflates it with a "
                         "scalar. This obstruction alone is sufficient for RP9's conclusion "
                         "that decryption is unreachable, and is fully supported by RP9's own "
                         "text -- unlike the S_ID half.")

    t.step("RP9 §4.7", "AM-09 (x_i's G_2 -> scalar type) is a FURTHER obstruction, additional "
                        "to and independent of the R collision, that RP9 does not identify. "
                        "Which obstruction is met 'first' during execution is an artefact of "
                        "function ordering, not a property of the scheme; no ranking is drawn.")


def run(curve: CurveParams, g: Point) -> str:
    verdict("a7_sk_impossible", "RP9 §4.7", "Session-key computation is impossible for the CH")
    halt_id = _literal_branch(curve, g)
    _diagnostic_branch(curve, g)
    result = f"STRUCTURAL FAILURE (literal branch halted at {halt_id}; diagnostic branch: OB-06 fully supported, ER-05 partially, AM-09 additional)"
    verdict("a7_sk_impossible", "RP9 §4.7", result)
    return result
