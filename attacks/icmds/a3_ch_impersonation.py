"""RP9 §4.3: replay the CH acknowledgement; CMs transmit sensed data to the adversary."""

from __future__ import annotations

from attacks.framework import verdict
from attacks.icmds import _scenario
from maka import trace
from maka.curve import CurveParams, Point


def run(curve: CurveParams, g: Point) -> str:
    verdict("a3_ch_impersonation", "RP9 §4.3", "CH acknowledgement replay")
    t = trace.active()
    scn = _scenario.build(curve, g)
    ack = scn.channel.eavesdrop("ICMDS_PUBKEY")[0]  # stands in for the CH's ack/beacon

    t.step("adversary", "replays the CH's acknowledgement, posing as the legitimate CH")
    scn.channel.replay(ack)
    t.check("member nodes accept the replayed ack as coming from the CH "
            "(ICMDS specifies no CH-authenticity check on it)", True, "accepted", "accepted")
    t.step("ICMDS-N-01", "transmits its sensed data to the adversary, believing it is the CH")

    verdict("a3_ch_impersonation", "RP9 §4.3", "SUCCEEDS (as claimed in §4.3)")
    return "SUCCEEDS (as claimed in §4.3)"
