"""ClusterHead: RP9 §5.3 (CH side), §5.4, §5.4.1, §5.5 responsibilities."""

from __future__ import annotations

from typing import ClassVar

from maka.curve import CurveParams, Point
from maka.entities.node import Node
from maka.wire import PAPER_SIZES


class ClusterHead(Node):
    STORAGE_FIELDS: ClassVar[list[tuple[str, int]]] = Node.STORAGE_FIELDS + [
        ("p_ch", PAPER_SIZES["point"]),
        ("p_cm_table_summary", 0),  # itemised separately per member; see P12.4
    ]

    def __init__(self, identity: str, curve: CurveParams, g: Point, id_bs: str, pu_bs: Point) -> None:
        super().__init__(identity, curve, g, id_bs, pu_bs)
        self.members: dict[str, Point] = {}  # ID_CM -> Pu_CM, from consumed PUB_CM frames (I-04)
        self.p_ch: Point | None = None
        self.p_cm_table: dict[str, Point] = {}  # ID_CM -> P_CM, decoded from PSEUDO_BS_CH
        self.p_cm_table_summary = None
        self.r_ch: int | None = None
        self.a1: Point | None = None
        self.a2: Point | None = None
        self.sk_ch_bs: object | None = None
        self.member_session_keys: dict[str, object] = {}  # SK_CM-BS is NOT held here (AM-05)
        self.authenticated_members: set[str] = set()

    def add_member(self, member_id: str, pu_cm: Point) -> None:
        self.members[member_id] = pu_cm
