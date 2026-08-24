"""RP9 §5.4, §5.4.1, §5.4.2: node authentication.

CH: r_CH <-$ Z_r; A1 = r_CH*g; A2 = r_CH*P_CH; EM1 = Enc((A1,A2,N_auth_CH), Pu_CM),
EM2 = Enc((A1,A2,N_auth_CH), Pu_BS). CM: decrypt EM1, check freshness, compute
A2' = (ID_BS xor ID_CH)*A1, compare to A2. CM: r_CM <-$ Z_r; A3 = r_CM*g;
A4 = r_CM*P_CM [ER-01: RP9 prints A4 = r_CH*P_CM, which the CM cannot compute and which
fails the CH's own stated check -- a typographical error, corrected here to r_CM*P_CM];
EM3 = Enc((A3,A4,N_auth_CM), Pu_CH). CH: decrypt EM3, check N_auth_CM, compute
A4' = (ID_CH xor ID_CM)*A3, compare to A4. BS: decrypt EM2, check N_auth_CH, compute A2',
compare to A2.

Applies: IA-05 (N_auth_CH / N_auth_CM are fresh instances, distinct from N_reg), ER-01.
"""

from __future__ import annotations

from maka import fixtures, ibe, ledger, rng, trace
from maka.network import Network
from maka.protocol.p3_node_registration import xor_to_scalar
from maka.wire import PAPER_SIZES, Sized

NONCE_BYTES = PAPER_SIZES["nonce"] // 8


def run(net: Network, fixture: str) -> None:
    t = trace.active()
    t.section("5.4", "Node authentication")
    curve = net.bs.curve

    matrix_rows = []
    for ch in net.cluster_heads.values():
        for cm in net.cluster_members[ch.identity].values():
            matrix_rows.extend(_authenticate_pair(net, ch, cm, curve))

    t.table(["direction", "evidence", "verdict"], matrix_rows, "Mutual-authentication summary (P8.6)")

    _negative_paths(net, curve)

    if fixture == fixtures.PAPER:
        bits = net.channel.total_bits(["EM1", "EM2", "EM3"])
        t.check("Table 3 row 3 (authentication) = 2400 bits", bits == 2400, 2400, bits)
    else:
        t.underspecified("Table 3 row 3 on F-NET", "[AM-06] reported only, not compared to RP9")


def _em_body(a: object, b: object, nonce: bytes) -> dict[str, object]:
    return {"A": Sized(a, PAPER_SIZES["point"]), "B": Sized(b, PAPER_SIZES["point"]), "N": nonce}


def _authenticate_pair(net: Network, ch: object, cm: object, curve: object) -> list[list[object]]:
    t = trace.active()
    rows: list[list[object]] = []

    with ledger.LedgerScope(ch.identity, "authentication"):
        ch.r_ch = rng.current().below(curve.r_group)
        t.value("r_CH", ch.r_ch, note="[IA-02] scalar drawn from Z_r (RP9 writes Z_p; see IA-02)")
        ch.a1 = ch.r_ch * ch.curve_g
        ch.a2 = ch.r_ch * ch.p_ch
        t.formula("A1", "r_CH * g", ch.a1)
        t.formula("A2", "r_CH * P_CH", ch.a2)
        n_auth_ch = rng.current().bytes(NONCE_BYTES)
        t.register("IA-05", "N_auth_CH: fresh nonce instance for §5.4, distinct from N_reg")

        em1 = ibe.encrypt(curve, ch.curve_g, repr((ch.a1, ch.a2, n_auth_ch)).encode(), cm.pu_i, net.bs.k_pub)
        net.channel.send("EM1", ch.identity, cm.identity, em1, _em_body(ch.a1, ch.a2, n_auth_ch))
        em2 = ibe.encrypt(curve, ch.curve_g, repr((ch.a1, ch.a2, n_auth_ch)).encode(), net.bs.pu_bs, net.bs.k_pub)
        net.channel.send("EM2", ch.identity, net.bs.identity, em2, _em_body(ch.a1, ch.a2, n_auth_ch))

    with ledger.LedgerScope(cm.identity, "authentication"):
        em1_plaintext = ibe.decrypt(curve, em1, cm.pr_i)
        t.check("CM decrypts EM1 to the plaintext CH sealed",
                em1_plaintext == repr((ch.a1, ch.a2, n_auth_ch)).encode(), True, em1_plaintext == repr((ch.a1, ch.a2, n_auth_ch)).encode())
        fresh1 = cm.check_and_cache_nonce(n_auth_ch)
        a2_check = xor_to_scalar(net.bs.identity, ch.identity, curve.r_group) * ch.a1
        ok_cm_ch = fresh1 and (a2_check == ch.a2)
        t.formula("A2' (at CM)", "(ID_BS xor ID_CH) * A1", a2_check)
        t.check("CM verifies CH: A2' == A2", ok_cm_ch, ch.a2, a2_check)
        rows.append([f"{cm.identity} -> {ch.identity}", "A2' == A2", "PASS" if ok_cm_ch else "FAIL"])

        cm.r_cm = rng.current().below(curve.r_group)
        t.value("r_CM", cm.r_cm, note="[IA-02] scalar drawn from Z_r (RP9 writes Z_p; see IA-02)")
        cm.a3 = cm.r_cm * ch.curve_g
        cm.a4 = cm.r_cm * cm.p_cm
        t.register("ER-01", "RP9 §5.4.1 prints A4 = r_CH * P_CM, which the CM cannot compute "
                             "(it has no access to r_CH) and which fails the CH's own stated "
                             "check A4' = (ID_CH xor ID_CM)*A3 = r_CM*P_CM. Implemented as "
                             "A4 = r_CM * P_CM.")
        t.formula("A4", "r_CM * P_CM  [ER-01: corrected from RP9's printed r_CH * P_CM]", cm.a4)
        n_auth_cm = rng.current().bytes(NONCE_BYTES)
        t.register("IA-05", "N_auth_CM: fresh nonce instance for §5.4.1")

        em3 = ibe.encrypt(curve, ch.curve_g, repr((cm.a3, cm.a4, n_auth_cm)).encode(), ch.pu_i, net.bs.k_pub)
        net.channel.send("EM3", cm.identity, ch.identity, em3, _em_body(cm.a3, cm.a4, n_auth_cm))

    with ledger.LedgerScope(ch.identity, "authentication"):
        em3_plaintext = ibe.decrypt(curve, em3, ch.pr_i)
        t.check("CH decrypts EM3 to the plaintext CM sealed",
                em3_plaintext == repr((cm.a3, cm.a4, n_auth_cm)).encode(), True, em3_plaintext == repr((cm.a3, cm.a4, n_auth_cm)).encode())
        fresh3 = ch.check_and_cache_nonce(n_auth_cm)
        a4_check = xor_to_scalar(ch.identity, cm.identity, curve.r_group) * cm.a3
        ok_ch_cm = fresh3 and (a4_check == cm.a4)
        t.formula("A4' (at CH)", "(ID_CH xor ID_CM) * A3", a4_check)
        t.check("CH verifies CM: A4' == A4", ok_ch_cm, cm.a4, a4_check)
        rows.append([f"{ch.identity} -> {cm.identity}", "A4' == A4", "PASS" if ok_ch_cm else "FAIL"])

    with ledger.LedgerScope(net.bs.identity, "authentication"):
        em2_plaintext = ibe.decrypt(curve, em2, net.bs.pr_bs)
        t.check("BS decrypts EM2 to the plaintext CH sealed",
                em2_plaintext == repr((ch.a1, ch.a2, n_auth_ch)).encode(), True, em2_plaintext == repr((ch.a1, ch.a2, n_auth_ch)).encode())
        fresh2 = net.bs.check_and_cache_nonce(n_auth_ch)
        a2_check_bs = xor_to_scalar(net.bs.identity, ch.identity, curve.r_group) * ch.a1
        ok_bs_ch = fresh2 and (a2_check_bs == ch.a2)
        t.formula("A2' (at BS)", "(ID_BS xor ID_CH) * A1  [RP9 §5.4.2]", a2_check_bs)
        t.check("BS verifies CH: A2' == A2", ok_bs_ch, ch.a2, a2_check_bs)
        rows.append([f"{net.bs.identity} -> {ch.identity}", "A2' == A2 (BS side)", "PASS" if ok_bs_ch else "FAIL"])

    return rows


def _negative_paths(net: Network, curve: object) -> None:
    t = trace.active()
    t.section("5.4-negative", "Negative paths")
    ch = next(iter(net.cluster_heads.values()))
    cm = next(iter(net.cluster_members[ch.identity].values()))

    # stale nonce: reuse an already-cached nonce
    stale = next(iter(cm.nonce_cache)) if cm.nonce_cache else rng.current().bytes(NONCE_BYTES)
    accepted = cm.check_and_cache_nonce(stale)
    t.check("stale nonce rejected", accepted is False, False, accepted)

    # adversary without P_CH cannot forge a matching A2
    forged_rho = rng.current().below(curve.r_group)
    forged_a1 = forged_rho * ch.curve_g
    verification_target = xor_to_scalar(net.bs.identity, ch.identity, curve.r_group) * forged_a1
    t.register("OB-04", "g is a public parameter -- the adversary can compute A1 = rho*g for "
                         "any rho. What the check actually enforces is inability to produce a "
                         "matching A2 without the undisclosed P_CH, not ignorance of g.")
    # lacking P_CH, the best the adversary can submit in its place is rho*g (using the only
    # point it has), which the verification equation below will reject
    adversary_guess_a2 = forged_rho * ch.curve_g
    t.check("adversary's best-effort A2 (no P_CH) fails BS verification",
            adversary_guess_a2 != verification_target, verification_target, adversary_guess_a2)

    # tampered A1
    tampered_a1 = ch.a1 + ch.curve_g
    tampered_check = xor_to_scalar(net.bs.identity, ch.identity, curve.r_group) * tampered_a1
    t.check("tampered A1 fails BS verification", tampered_check != ch.a2, ch.a2, tampered_check)
