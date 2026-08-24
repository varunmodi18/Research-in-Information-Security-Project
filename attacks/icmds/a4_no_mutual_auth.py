"""RP9 §4.4: structural -- message-flow diff against MAKA showing no CM->CH authentication
step exists in ICMDS."""

from __future__ import annotations

from attacks.framework import verdict
from maka import trace
from maka.curve import CurveParams, Point

MAKA_FLOW = ["BEACON (CH->BS)", "PSEUDO_BS_CH (BS->CH)", "PSEUDO_CH_CM (CH->CM)",
             "EM1 (CH->CM)", "EM2 (CH->BS)", "EM3 (CM->CH, CM authenticates to CH)",
             "SESSION_KEY (implicit, no message)"]
ICMDS_FLOW = ["beacon (pre-distributed key + CM ids)", "BS generates per-node public key",
              "CH re-checks public key", "gateway key setup (S_ID)", "encryption/decryption"]


def run(curve: CurveParams, g: Point) -> str:
    verdict("a4_no_mutual_auth", "RP9 §4.4", "Structural: no CM->CH authentication step")
    t = trace.active()
    t.table(["MAKA §5 message flow"], [[m] for m in MAKA_FLOW], "MAKA (has EM3: CM authenticates to CH)")
    t.table(["ICMDS §3 message flow"], [[m] for m in ICMDS_FLOW], "ICMDS (no CM->CH authentication step)")
    t.check("ICMDS flow contains a step where the CM authenticates itself to the CH",
            False, "present (as in MAKA's EM3)", "absent")
    verdict("a4_no_mutual_auth", "RP9 §4.4", "SUCCEEDS (as claimed in §4.4)")
    return "SUCCEEDS (as claimed in §4.4)"
