"""RP9 §5.2: node key generation.

Each node computes Pu_i = H(ID_i), Pr_i = k*Pu_i, then destroys k (overwrite plus attribute
deletion) and publishes Pu_i. Cross-checks e(Pr_i, Pu_BS) == e(Pu_i, Pr_BS) as a preview of
§5.5's session-key agreement.
"""

from __future__ import annotations

from maka import ledger, pairing, trace
from maka.network import Network


def run(net: Network) -> None:
    t = trace.active()
    t.section("5.2", "Node key generation")

    with ledger.LedgerScope(net.bs.identity, "keygen"):
        net.bs.destroy_master_key()

    for ch in net.cluster_heads.values():
        with ledger.LedgerScope(ch.identity, "keygen"):
            ch.compute_keys_and_destroy_k()
        for cm in net.cluster_members[ch.identity].values():
            with ledger.LedgerScope(cm.identity, "keygen"):
                cm.compute_keys_and_destroy_k()

    t.section("5.5-preview", "Cross-check e(Pr_i, Pu_BS) = e(Pu_i, Pr_BS)")
    for ch in net.cluster_heads.values():
        _cross_check(net, ch.identity, ch.pr_i, ch.pu_i)
        for cm in net.cluster_members[ch.identity].values():
            _cross_check(net, cm.identity, cm.pr_i, cm.pu_i)


def _cross_check(net: Network, ident: str, pr_i: object, pu_i: object) -> None:
    t = trace.active()
    lhs = pairing.modified_pairing(net.bs.curve, pr_i, net.bs.pu_bs)  # type: ignore[arg-type]
    rhs = pairing.modified_pairing(net.bs.curve, pu_i, net.bs.pr_bs)  # type: ignore[arg-type]
    t.check(f"e(Pr_{ident}, Pu_BS) = e(Pu_{ident}, Pr_BS)", lhs == rhs, rhs, lhs)
