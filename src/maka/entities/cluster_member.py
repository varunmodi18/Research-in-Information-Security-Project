"""ClusterMember: RP9 §5.3 (CM side), §5.4.1, §5.5 responsibilities."""

from __future__ import annotations

from typing import ClassVar

from maka.curve import CurveParams, Point
from maka.entities.node import Node
from maka.wire import PAPER_SIZES


class ClusterMember(Node):
    STORAGE_FIELDS: ClassVar[list[tuple[str, int]]] = Node.STORAGE_FIELDS + [
        ("id_ch", PAPER_SIZES["id"]),
        ("p_cm", PAPER_SIZES["point"]),
    ]

    def __init__(self, identity: str, curve: CurveParams, g: Point, id_bs: str, pu_bs: Point,
                 id_ch: str) -> None:
        super().__init__(identity, curve, g, id_bs, pu_bs)
        self.id_ch = id_ch
        self.p_cm: Point | None = None
        self.r_cm: int | None = None
        self.a3: Point | None = None
        self.a4: Point | None = None
        self.sk_cm_bs: object | None = None
