"""RP9 §5.5: session key agreement.

Node: SK_{i-BS} = e(Pr_i, Pu_BS); BS: SK_{BS-i} = e(Pu_i, Pr_BS), with Pu_i as the BS decoded
it from PUB_CH / BEACON frames. Only nodes that completed §5.4 take part (I-07). Contributes
0 messages: Table 3 row 4 counts every frame sent while this phase runs (I-12). Demonstrates
OB-02 (no forward secrecy -- the key never changes across repeated runs of this phase).
"""

from __future__ import annotations

from maka import fixtures, hashing, ledger, pairing, trace
from maka.entities.cluster_head import ClusterHead
from maka.field import fp2_to_bytes
from maka.network import Network

K_SYM_BYTES = 32


def k_sym_label(id_bs: str, ident: str) -> bytes:
    return f"MAKA-DATA{id_bs}{ident}".encode()


def _agree(net: Network, ident: str, pr_i: object) -> bytes | None:
    t = trace.active()
    curve = net.bs.curve
    pu_i = net.bs.public_key_of(ident)
    if pu_i is None:
        t.step(net.bs.identity, f"no decoded public key for {ident}; no session key")
        return None
    with ledger.LedgerScope(ident, "session_key"):
        sk_node = pairing.modified_pairing(curve, pr_i, net.bs.pu_bs)  # type: ignore[arg-type]
        t.secret(f"SK_{{{ident}-BS}}", sk_node, note="= e(Pr, Pu_BS)")
    with ledger.LedgerScope(net.bs.identity, "session_key"):
        sk_bs = pairing.modified_pairing(curve, pu_i, net.bs.pr_bs)  # type: ignore[arg-type]
        t.secret(f"SK_{{BS-{ident}}}", sk_bs, note="= e(Pu, Pr_BS)")
    t.check(f"SK_{{{ident}-BS}} == SK_{{BS-{ident}}}", sk_node == sk_bs,
            t.redacted(f"SK_{{BS-{ident}}}", sk_bs), t.redacted(f"SK_{{{ident}-BS}}", sk_node))
    net.bs.session_keys[ident] = sk_bs

    label = k_sym_label(net.bs.identity, ident)
    k_sym_node = hashing.kdf(fp2_to_bytes(sk_node), label, K_SYM_BYTES)
    k_sym_bs = hashing.kdf(fp2_to_bytes(sk_bs), label, K_SYM_BYTES)
    net.bs.sym_keys[ident] = k_sym_bs
    t.register("IA-06", "k_sym = KDF('MAKA-DATA' || ID_BS || ID_i || SK_i-BS)")
    t.check(f"k_sym agreement ({ident})", k_sym_node == k_sym_bs,
            t.redacted(f"k_sym BS-{ident}", k_sym_bs), t.redacted(f"k_sym {ident}-BS", k_sym_node))
    return k_sym_node


def eligible_members(net: Network, ch: ClusterHead) -> list[str]:
    """CMs that verified their CH *and* were verified by it in §5.4."""
    return [cm.identity for cm in net.cluster_members[ch.identity].values()
            if not cm.failed and cm.ch_verified and cm.identity in ch.authenticated_members]


def run(net: Network, fixture: str) -> None:
    t = trace.active()
    t.section("5.5", "Session key agreement")
    start = len(net.channel.frames)
    keys: dict[str, bytes] = {}

    for ch in net.cluster_heads.values():
        if ch.failed:
            t.step(ch.identity, f"excluded from session key agreement: {ch.failure_reason}")
            continue
        key = _agree(net, ch.identity, ch.pr_i)
        if key is not None:
            keys[ch.identity] = key
            ch.sk_ch_bs = net.bs.session_keys[ch.identity]
        eligible = eligible_members(net, ch)
        for cm in net.cluster_members[ch.identity].values():
            if cm.identity not in eligible:
                t.step(cm.identity, "excluded from session key agreement: not mutually "
                                    f"authenticated ({cm.failure_reason or 'no verification'})")
                continue
            key = _agree(net, cm.identity, cm.pr_i)
            if key is not None:
                keys[cm.identity] = key
                cm.sk_cm_bs = net.bs.session_keys[cm.identity]

    t.section("5.5-OB-02", "No forward secrecy: repeat the phase, compare keys")
    agreed = [ch for ch in net.cluster_heads.values() if ch.identity in keys]
    if agreed:
        ch = agreed[0]
        sk_first = net.bs.session_keys[ch.identity]
        sk_second = pairing.modified_pairing(net.bs.curve, ch.pr_i, ch.pu_bs)  # type: ignore[arg-type]
        t.register("OB-02", "SK_{i-BS} depends only on Pu_i, Pu_BS and k -- no ephemeral input, "
                             "never changes, no forward secrecy. Demonstrated by bit-identical "
                             "recomputation; ephemerality is NOT added.")
        t.check("SK_{CH-BS} identical across two computations (OB-02)", sk_first == sk_second,
                t.redacted("SK first", sk_first), t.redacted("SK second", sk_second))

    if fixture == fixtures.PAPER:
        bits = net.channel.bits_since(start)
        t.check("Table 3 row 4 (session key agreement) = 0 bits: every frame sent during §5.5",
                bits == 0, 0, bits)

    net.sym_keys.update(keys)
