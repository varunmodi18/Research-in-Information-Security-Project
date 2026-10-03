"""ClusterMember: RP9 §5.3 (CM side), §5.4.1, §5.5 responsibilities."""

from __future__ import annotations

from typing import ClassVar

from maka.curve import CurveParams, Point
from maka.entities.node import Node
from maka.wire import PAPER_SIZES


class ClusterMember(Node):
    # Sizes follow RP9's paper model: id/nonce/random number/shared key = 160 bits (§7.2, §8),
    # point = 320 bits. Fields are counted while present; nothing is deleted after use (AM-07).
    STORAGE_FIELDS: ClassVar[list[tuple[str, int]]] = Node.STORAGE_FIELDS + [
        ("id_ch", PAPER_SIZES["id"]),
        ("p_cm", PAPER_SIZES["point"]),
        ("r_cm", PAPER_SIZES["nonce"]),
        ("a3", PAPER_SIZES["point"]),
        ("a4", PAPER_SIZES["point"]),
        ("sk_cm_bs", PAPER_SIZES["nonce"]),
    ]

    def __init__(self, identity: str, curve: CurveParams, g: Point, id_bs: str, pu_bs: Point,
                 id_ch: str) -> None:
        super().__init__(identity, curve, g, id_bs, pu_bs)
        # The cluster this CM is deployed into (fixture configuration, used by the driver to
        # route frames). The CM's *protocol* view of its CH, `id_ch`, is learned from the
        # decoded PSEUDO_CH_CM message (IA-14) and stays None until then.
        self.deployed_cluster = id_ch
        self.id_ch: str | None = None
        self.pu_ch: Point | None = None  # overheard from the CH's PUB_CH broadcast (IA-08)
        self.p_cm: Point | None = None
        self.r_cm: int | None = None
        self.a3: Point | None = None
        self.a4: Point | None = None
        self.sk_cm_bs: object | None = None
        self.ch_verified = False
