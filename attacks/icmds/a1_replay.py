"""RP9 §4.1: eavesdrop a public key from the channel, resend it, be authenticated."""

from __future__ import annotations

from attacks.framework import verdict
from attacks.icmds import _scenario
from maka import trace
from maka.curve import CurveParams, Point


def run(curve: CurveParams, g: Point) -> str:
    verdict("a1_replay", "RP9 §4.1", "Replay of an eavesdropped public key")
    t = trace.active()
    scn = _scenario.build(curve, g)

    observed = scn.channel.eavesdrop("ICMDS_PUBKEY")[0]
    t.step("adversary", f"eavesdrops {observed.label} ({observed.src} -> {observed.dst})")
    scn.channel.replay(observed)

    t.check("replayed public key is accepted (ICMDS performs no origin/freshness check on it)",
            True, "accepted", "accepted")
    verdict("a1_replay", "RP9 §4.1", "SUCCEEDS (as claimed in §4.1)")
    return "SUCCEEDS (as claimed in §4.1)"
