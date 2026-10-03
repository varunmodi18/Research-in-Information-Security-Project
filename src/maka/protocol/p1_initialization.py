"""RP9 §5.1: system initialisation.

Realises: RP9 §5.1. Applies: IA-02 (scalar domain Z_r), IA-03 (K_pub scaffolding), OB-01
(master key held until destruction).

BS generates (E, F_p, G, g, r, k, H); computes Pu_BS = H(ID_BS), Pr_BS = k*Pu_BS. Every
node is preloaded with (ID, p, g, k, H, ID_BS, Pu_BS) exactly as §5.1 states.
"""

from __future__ import annotations

from maka import fixtures, ledger, rng, trace
from maka.channel import Channel
from maka.curve import CurveParams, Point
from maka.entities.base_station import BaseStation
from maka.entities.cluster_head import ClusterHead
from maka.entities.cluster_member import ClusterMember
from maka.network import Network


def run(curve: CurveParams, g: Point, fixture: str) -> Network:
    t = trace.active()
    t.section("5.1", "System initialisation")
    topo = fixtures.topology(fixture)

    bs = BaseStation(str(topo["bs"]), curve, g)
    with ledger.LedgerScope(bs.identity, "init"):
        k_scalar = rng.current().randint(1, curve.r_group)
        t.secret("k (master key)", k_scalar, note="[I-09: never printed; --disclose-secrets shows it]")
        bs.generate_parameters(k_scalar)
    assert bs.pu_bs is not None and bs.k_pub is not None  # type narrowing only

    net = Network(bs=bs, channel=Channel())

    for ch_id, member_ids in topo["chs"].items():  # type: ignore[union-attr]
        t.step(ch_id, "preloaded with (ID, p_field, g, k, H, ID_BS, Pu_BS)")
        ch = ClusterHead(ch_id, curve, g, bs.identity, bs.pu_bs)
        ch.preload(k_scalar, bs.k_pub)
        net.add_cluster_head(ch)
        for cm_id in member_ids:  # type: ignore[union-attr]
            t.step(cm_id, "preloaded with (ID, p_field, g, k, H, ID_BS, Pu_BS)")
            cm = ClusterMember(cm_id, curve, g, bs.identity, bs.pu_bs, id_ch=ch_id)
            cm.preload(k_scalar, bs.k_pub)
            net.add_cluster_member(ch_id, cm)

    return net
