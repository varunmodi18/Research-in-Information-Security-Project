"""RP9 §5.2: node key generation.

Each node computes Pu_i = H(ID_i), Pr_i = k*Pu_i, then deletes k and publishes Pu_i as an
encoded PUB_CH / PUB_CM frame (maka.codec). Cross-checks e(Pr_i, Pu_BS) == e(Pu_i, Pr_BS) as
a preview of §5.5's session-key agreement; both sides are SECRET and are not printed.
"""

from __future__ import annotations

from maka import codec, ledger, pairing, trace
from maka.network import Network
from maka.wire import PAPER_SIZES, Sized


def run(net: Network) -> None:
    t = trace.active()
    t.section("5.2", "Node key generation")

    with ledger.LedgerScope(net.bs.identity, "keygen"):
        net.bs.destroy_master_key()

    for ch in net.cluster_heads.values():
        with ledger.LedgerScope(ch.identity, "keygen"):
            ch.compute_keys_and_destroy_k()
        assert ch.pu_i is not None  # type narrowing only
        net.channel.send("PUB_CH", ch.identity, net.bs.identity, codec.encode_pub(ch.pu_i),
                          {"Pu_CH": Sized(ch.pu_i, PAPER_SIZES["point"])})
        for cm in net.cluster_members[ch.identity].values():
            with ledger.LedgerScope(cm.identity, "keygen"):
                cm.compute_keys_and_destroy_k()
            assert cm.pu_i is not None  # type narrowing only
            net.channel.send("PUB_CM", cm.identity, ch.identity, codec.encode_pub(cm.pu_i),
                              {"Pu_CM": Sized(cm.pu_i, PAPER_SIZES["point"])})

    t.section("5.5-preview", "Cross-check e(Pr_i, Pu_BS) = e(Pu_i, Pr_BS)")
    for ch in net.cluster_heads.values():
        _cross_check(net, ch.identity, ch.pr_i, ch.pu_i)
        for cm in net.cluster_members[ch.identity].values():
            _cross_check(net, cm.identity, cm.pr_i, cm.pu_i)


def _cross_check(net: Network, ident: str, pr_i: object, pu_i: object) -> None:
    t = trace.active()
    lhs = pairing.modified_pairing(net.bs.curve, pr_i, net.bs.pu_bs)  # type: ignore[arg-type]
    rhs = pairing.modified_pairing(net.bs.curve, pu_i, net.bs.pr_bs)  # type: ignore[arg-type]
    t.check(f"e(Pr_{ident}, Pu_BS) = e(Pu_{ident}, Pr_BS)", lhs == rhs,
            t.redacted(f"e(Pu_{ident}, Pr_BS)", rhs), t.redacted(f"e(Pr_{ident}, Pu_BS)", lhs))
