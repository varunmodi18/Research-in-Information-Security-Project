"""RP9 §5.5: session key agreement.

Node: SK_{i-BS} = e(Pr_i, Pu_BS); BS: SK_{BS-i} = e(Pu_i, Pr_BS). Contributes 0 messages
(Table 3 row 4). Demonstrates OB-02 (no forward secrecy -- the key never changes across
repeated runs of this phase).
"""

from __future__ import annotations

from maka import fixtures, hashing, ledger, pairing, trace
from maka.network import Network

K_SYM_BYTES = 32


def _agree(net: Network, ident: str, pr_i: object, pu_i: object) -> object:
    t = trace.active()
    curve = net.bs.curve
    with ledger.LedgerScope(ident, "session_key"):
        sk_node = pairing.modified_pairing(curve, pr_i, net.bs.pu_bs)  # type: ignore[arg-type]
        t.formula(f"SK_{{{ident}-BS}}", "e(Pr, Pu_BS)", sk_node)
    with ledger.LedgerScope(net.bs.identity, "session_key"):
        sk_bs = pairing.modified_pairing(curve, pu_i, net.bs.pr_bs)  # type: ignore[arg-type]
        t.formula(f"SK_{{BS-{ident}}}", "e(Pu, Pr_BS)", sk_bs)
    t.check(f"SK_{{{ident}-BS}} == SK_{{BS-{ident}}}", sk_node == sk_bs, sk_bs, sk_node)
    net.bs.session_keys[ident] = sk_bs

    from maka.field import fp2_to_bytes
    k_sym_node = hashing.kdf(fp2_to_bytes(sk_node), f"MAKA-DATA{net.bs.identity}{ident}".encode(), K_SYM_BYTES)
    k_sym_bs = hashing.kdf(fp2_to_bytes(sk_bs), f"MAKA-DATA{net.bs.identity}{ident}".encode(), K_SYM_BYTES)
    t.register("IA-06", "k_sym = KDF('MAKA-DATA' || ID_i || ID_BS || SK_i-BS)")
    t.check(f"k_sym agreement ({ident})", k_sym_node == k_sym_bs, k_sym_bs[:8], k_sym_node[:8])
    return k_sym_node


def run(net: Network, fixture: str) -> None:
    t = trace.active()
    t.section("5.5", "Session key agreement")
    keys: dict[str, bytes] = {}

    for ch in net.cluster_heads.values():
        keys[ch.identity] = _agree(net, ch.identity, ch.pr_i, ch.pu_i)
        ch.sk_ch_bs = net.bs.session_keys[ch.identity]
        for cm in net.cluster_members[ch.identity].values():
            keys[cm.identity] = _agree(net, cm.identity, cm.pr_i, cm.pu_i)
            cm.sk_cm_bs = net.bs.session_keys[cm.identity]

    t.section("5.5-OB-02", "No forward secrecy: repeat the phase, compare keys")
    ch = next(iter(net.cluster_heads.values()))
    sk_first = net.bs.session_keys[ch.identity]
    sk_second = pairing.modified_pairing(net.bs.curve, ch.pr_i, net.bs.pu_bs)  # type: ignore[arg-type]
    t.register("OB-02", "SK_{i-BS} depends only on Pu_i, Pu_BS and k -- no ephemeral input, "
                         "never changes, no forward secrecy. Demonstrated by bit-identical "
                         "recomputation; ephemerality is NOT added.")
    t.check("SK_{CH-BS} identical across two computations (OB-02)", sk_first == sk_second, sk_first, sk_second)

    if fixture == fixtures.PAPER:
        bits = net.channel.total_bits(["SESSION_KEY_MSG"])
        t.check("Table 3 row 4 (session key agreement) = 0 bits (zero-message property)",
                bits == 0, 0, bits)

    net.sym_keys.update(keys)
