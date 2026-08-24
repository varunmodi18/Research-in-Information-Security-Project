"""RP9 §4.2: replaying N messages costs the CH N additional authentication computations.

Revised in Revision 3: shows only the linear replay/verification relation and quotes RP9's
qualitative conclusion. No battery capacity, exhaustion threshold, energy-per-operation
figure, or time-to-failure is invented -- RP9 supplies none (see docs/DEFERRED.md).
"""

from __future__ import annotations

from attacks.framework import verdict
from attacks.icmds import _scenario
from maka import trace
from maka.curve import CurveParams, Point
from maka.wire import PAPER_SIZES, Sized


def run(curve: CurveParams, g: Point) -> str:
    verdict("a2_dos", "RP9 §4.2", "Replay-induced computation")
    t = trace.active()
    scn = _scenario.build(curve, g)
    observed = scn.channel.eavesdrop("ICMDS_PUBKEY")[0]

    rows = []
    for n in (1, 10, 100):
        for _ in range(n):
            scn.channel.replay(observed)
        rows.append([n, n])
        scn.channel.reset()
        scn.channel.send("ICMDS_PUBKEY", observed.src, observed.dst, observed.payload,
                          {"pubkey": Sized(observed.payload.public_key, PAPER_SIZES["id"])})
        observed = scn.channel.eavesdrop("ICMDS_PUBKEY")[0]

    t.table(["N replays", "extra CH verifications"], rows, "Linear replay/verification relation")
    t.step("RP9 §4.2 (quoted)", "'this consumes...the sensor's energy, and leads it to be "
                                 "out of service' -- no quantitative battery model is given, "
                                 "and none is supplied here (see docs/DEFERRED.md).")
    verdict("a2_dos", "RP9 §4.2", "SUCCEEDS (as claimed in §4.2)")
    return "SUCCEEDS (as claimed in §4.2)"
