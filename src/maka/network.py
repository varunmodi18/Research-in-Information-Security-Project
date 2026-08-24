"""Network container and ASCII rendering of RP9 Fig. 1 (P5.6)."""

from __future__ import annotations

from dataclasses import dataclass, field

from maka.channel import Channel
from maka.entities.base_station import BaseStation
from maka.entities.cluster_head import ClusterHead
from maka.entities.cluster_member import ClusterMember


@dataclass
class Network:
    bs: BaseStation
    cluster_heads: dict[str, ClusterHead] = field(default_factory=dict)
    cluster_members: dict[str, dict[str, ClusterMember]] = field(default_factory=dict)  # ch_id -> {cm_id: CM}
    channel: Channel = field(default_factory=Channel)
    sym_keys: dict[str, bytes] = field(default_factory=dict)  # ident -> k_sym, from P5

    def add_cluster_head(self, ch: ClusterHead) -> None:
        self.cluster_heads[ch.identity] = ch
        self.cluster_members[ch.identity] = {}

    def add_cluster_member(self, ch_id: str, cm: ClusterMember) -> None:
        self.cluster_members[ch_id][cm.identity] = cm

    def render_ascii(self) -> str:
        lines = [f"BS({self.bs.identity})"]
        for ch_id, ch in self.cluster_heads.items():
            lines.append(f"  |-- CH({ch_id})")
            for cm_id in self.cluster_members.get(ch_id, {}):
                lines.append(f"  |     |-- CM({cm_id})")
        return "\n".join(lines)
