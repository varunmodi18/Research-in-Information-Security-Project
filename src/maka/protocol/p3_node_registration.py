"""RP9 §5.3: node registration.

CH assembles the beacon (ID_CH, [ID_CM...], [Pu_CM...], N_reg), encrypts under Pu_BS, sends.
BS decrypts, checks N_reg against its nonce cache, computes P_CH = (ID_BS xor ID_CH)*g and
P_CM = (ID_CH xor ID_CM)*g. BS sends (P_CH, P_CM...) to the CH under IA-04; CH forwards each
P_CM.

Applies: IA-05 (N_reg is the registration-nonce instance), IA-04 ('sent securely' as
Enc(*, Pu_recipient)), AM-06/F-PAPER (Table 3 row 2 hard assertion only on F-PAPER).
"""

from __future__ import annotations

from maka import fixtures, ibe, ledger, rng, trace
from maka.network import Network
from maka.wire import PAPER_SIZES, Sized

NONCE_BYTES = PAPER_SIZES["nonce"] // 8


def xor_to_scalar(id_a: str, id_b: str, r_group: int) -> int:
    """(ID_BS xor ID_CH) as RP9 writes it, reduced into the scalar domain Z_r_group (IA-02:
    RP9's Z_p substituted by Z_r_group for our subgroup instantiation)."""
    a = int.from_bytes(id_a.encode(), "big")
    b = int.from_bytes(id_b.encode(), "big")
    return (a ^ b) % r_group


def run(net: Network, fixture: str) -> None:
    t = trace.active()
    t.section("5.3", "Node registration")
    curve = net.bs.curve

    for ch in net.cluster_heads.values():
        _register_cluster(net, ch, curve)

    if fixture == fixtures.PAPER:
        beacon_bits = net.channel.total_bits(["BEACON"])
        pseudo_bs_ch_bits = net.channel.total_bits(["PSEUDO_BS_CH"])
        pseudo_ch_cm_bits = net.channel.total_bits(["PSEUDO_CH_CM"])
        t.check("Table 3 row 2 (registration) = 1760 bits",
                beacon_bits + pseudo_bs_ch_bits + pseudo_ch_cm_bits == 1760,
                1760, beacon_bits + pseudo_bs_ch_bits + pseudo_ch_cm_bits)
        t.check("BEACON = 800 bits", beacon_bits == 800, 800, beacon_bits)
        t.check("BS->CH (PSEUDO_BS_CH) = 640 bits", pseudo_bs_ch_bits == 640, 640, pseudo_bs_ch_bits)
        t.check("CH->CM (PSEUDO_CH_CM) = 320 bits", pseudo_ch_cm_bits == 320, 320, pseudo_ch_cm_bits)
    else:
        t.underspecified("Table 3 row 2 on F-NET",
                          "[AM-06] RP9 never states the topology its cost tables assume; "
                          "F-NET's totals are reported only, never compared against RP9's tables")
        t.value("F-NET registration bits (reported only)",
                net.channel.total_bits(["BEACON", "PSEUDO_BS_CH", "PSEUDO_CH_CM"]))


def _send_beacon(net: Network, ch: "object", n_reg: bytes) -> "object":
    curve = net.bs.curve
    member_ids = list(ch.members.keys())
    plaintext_summary = {
        "ID_CH": ch.identity, "ID_CM": member_ids, "Pu_CM": list(ch.members.values()), "N_reg": n_reg,
    }
    ciphertext = ibe.encrypt(curve, ch.curve_g,
                              repr(plaintext_summary).encode(), net.bs.pu_bs, net.bs.k_pub)
    body = {
        "ID_CH": Sized(ch.identity, PAPER_SIZES["id"]),
        "ID_CM(s)": Sized(member_ids, PAPER_SIZES["id"] * len(member_ids)),
        "Pu_CM(s)": Sized(list(ch.members.values()), PAPER_SIZES["point"] * len(member_ids)),
        "N_reg": n_reg,
    }
    net.channel.send("BEACON", ch.identity, net.bs.identity, ciphertext, body)
    return ciphertext


def _register_cluster(net: Network, ch: "object", curve: "object") -> None:
    t = trace.active()
    for cm in net.cluster_members[ch.identity].values():
        ch.add_member(cm.identity, cm.pu_i)

    with ledger.LedgerScope(ch.identity, "registration"):
        n_reg = rng.current().bytes(NONCE_BYTES)
        t.step(ch.identity, "assembling beacon (ID_CH, [ID_CM...], [Pu_CM...], N_reg)")
        _send_beacon(net, ch, n_reg)

    with ledger.LedgerScope(net.bs.identity, "registration"):
        fresh = net.bs.check_and_cache_nonce(n_reg)
        assert fresh, "fresh registration should never collide on first send"

        p_ch_scalar = xor_to_scalar(net.bs.identity, ch.identity, curve.r_group)
        p_ch = p_ch_scalar * ch.curve_g
        t.formula("P_CH", "(ID_BS xor ID_CH) * g", p_ch)

        p_cm_points = {}
        for cm_id in ch.members:
            p_cm_scalar = xor_to_scalar(ch.identity, cm_id, curve.r_group)
            p_cm = p_cm_scalar * ch.curve_g
            p_cm_points[cm_id] = p_cm
            t.formula(f"P_{cm_id}", "(ID_CH xor ID_CM) * g", p_cm)

        net.channel.send(
            "PSEUDO_BS_CH", net.bs.identity, ch.identity, (p_ch, p_cm_points),
            {"P_CH": Sized(p_ch, PAPER_SIZES["point"]),
             "P_CM(s)": Sized(list(p_cm_points.values()), PAPER_SIZES["point"] * len(p_cm_points))})

    with ledger.LedgerScope(ch.identity, "registration"):
        ch.p_ch = p_ch
        ch.p_cm_table = dict(p_cm_points)
        for cm_id, p_cm in p_cm_points.items():
            net.channel.send("PSEUDO_CH_CM", ch.identity, cm_id, p_cm,
                              {"P_CM": Sized(p_cm, PAPER_SIZES["point"])})
            net.cluster_members[ch.identity][cm_id].p_cm = p_cm

    _demonstrate_replay_rejection(net, ch, n_reg)


def _demonstrate_replay_rejection(net: Network, ch: "object", n_reg: bytes) -> None:
    t = trace.active()
    t.step("adversary", f"replaying the {ch.identity} beacon's N_reg")
    accepted = net.bs.check_and_cache_nonce(n_reg)
    t.check("replayed BEACON is rejected", accepted is False, False, accepted)
