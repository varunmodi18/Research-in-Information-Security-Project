"""Minimal shared ICMDS scenario used by the RP9 §4 attack demonstrations.

RP9's §4 review is a paragraph per attack, not a full protocol trace; this scenario supplies
just enough ICMDS state (a gateway/BS setup, two node public keys, a channel) for each attack
to demonstrate the specific mechanism RP9 describes.
"""

from __future__ import annotations

from dataclasses import dataclass

from icmds import scheme, session_key
from maka import rng
from maka.channel import Channel
from maka.curve import CurveParams, Point
from maka.wire import PAPER_SIZES, Sized


@dataclass
class IcmdsScenario:
    curve: CurveParams
    g: Point
    channel: Channel
    setup_params: session_key.SetupParams
    ch_id: str
    node_ids: list[str]
    node_pubkeys: dict[str, object]


def build(curve: CurveParams, g: Point) -> IcmdsScenario:
    channel = Channel()
    s = rng.current().below(curve.r_group)
    setup_params = session_key.setup(curve, g, s)
    ch_id = "ICMDS-CH-01"
    node_ids = ["ICMDS-N-01", "ICMDS-N-02"]
    node_pubkeys = {}
    for nid in node_ids:
        pk_node = scheme.bs_generate_public_key(nid, distance=3, bs_stamp=b"stamp")
        node_pubkeys[nid] = pk_node
        channel.send("ICMDS_PUBKEY", ch_id, nid, pk_node,
                      {"pubkey": Sized(pk_node.public_key, PAPER_SIZES["id"])})
    return IcmdsScenario(curve=curve, g=g, channel=channel, setup_params=setup_params,
                          ch_id=ch_id, node_ids=node_ids, node_pubkeys=node_pubkeys)
