"""RP9 §4.6: node capture / session-key leakage -- a CONDITIONAL demonstration.

RP9 §4.6 presupposes a CH that has already successfully decrypted the session key; RP9 §4.7
then argues the scheme cannot reach that state. Both are RP9's own claims and cannot both be
literal executable outcomes (Revision 4). This module opens with a printed CONDITIONAL
SCENARIO banner; the key state is seeded as the premise of the security argument, never
produced by running the real §3 decryption path.
"""

from __future__ import annotations

from attacks.framework import verdict
from attacks.icmds import _scenario
from maka import rng, trace
from maka.aead import decrypt as aead_decrypt
from maka.aead import encrypt as aead_encrypt
from maka.curve import CurveParams, Point


def run(curve: CurveParams, g: Point) -> str:
    verdict("a6_node_capture", "RP9 §4.6", "Node capture under the presupposed session-key state")
    t = trace.active()
    t.conditional(
        premise="the session key S_k has been successfully recovered, as RP9 §4.6 presupposes",
        source="RP9 §4.6",
        caveat="this does not imply the literal §3 protocol can reach this state; §4.7 tests "
               "that separately in a7_sk_impossible.py",
    )
    scn = _scenario.build(curve, g)

    # Seeded directly as the premise -- NOT produced by icmds.session_key's decryption path.
    seeded_s_k = rng.current().bytes(16)
    t.value("S_k (seeded premise, [CONDITIONAL SCENARIO])", seeded_s_k)

    inter_cluster_traffic = aead_encrypt(seeded_s_k, b"inter-cluster-reading=19.2C")

    t.step("adversary", "captures the CH, extracts S_k from its memory")
    recovered = seeded_s_k  # node capture yields whatever the CH holds in memory

    plaintext = aead_decrypt(recovered, inter_cluster_traffic)
    t.check("adversary decrypts recorded inter-cluster traffic using the captured S_k",
            plaintext == b"inter-cluster-reading=19.2C", b"inter-cluster-reading=19.2C", plaintext)

    verdict("a6_node_capture", "RP9 §4.6", "SUCCEEDS UNDER THE STATED PREMISE (RP9 §4.6)")
    return "SUCCEEDS UNDER THE STATED PREMISE (RP9 §4.6)"
