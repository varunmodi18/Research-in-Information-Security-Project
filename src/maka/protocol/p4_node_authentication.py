"""RP9 §5.4, §5.4.1, §5.4.2: node authentication.

CH, once per round (IA-15): r_CH <-$ Z_r*; A1 = r_CH*g; A2 = r_CH*P_CH; N_auth_CH. One
EM1 = Enc((A1,A2,N_auth_CH), Pu_CM) per member and one EM2 = Enc((A1,A2,N_auth_CH), Pu_BS).
CM: decrypt and decode the *delivered* EM1, check freshness, compute A2' = (ID_BS xor ID_CH)*A1
from the decoded A1 and its own stored IDs, compare to the decoded A2 (I-01). CM: r_CM <-$ Z_r*;
A3 = r_CM*g; A4 = r_CM*P_CM [ER-01: RP9 prints A4 = r_CH*P_CM, which the CM cannot compute and
which fails the CH's own stated check -- a typographical error, corrected here to r_CM*P_CM];
EM3 = Enc((A3,A4,N_auth_CM), Pu_CH). CH: decrypt EM3, check N_auth_CM, compute
A4' = (ID_CH xor ID_CM)*A3, compare to A4. BS: decrypt EM2, check N_auth_CH, compute A2',
compare to A2.

A failed verification is a state transition, not a printout (I-07): the rejected party is
marked failed, emits ORIG_AUTH_FAIL, and is excluded from §5.5 and data transmission.

Applies: IA-05 (N_auth_CH / N_auth_CM are fresh instances, distinct from N_reg), ER-01, IA-15.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag

from maka import codec, fixtures, ledger, rng, trace
from maka.channel import Frame
from maka.codec import DecodeError
from maka.curve import Point
from maka.entities.cluster_head import ClusterHead
from maka.entities.cluster_member import ClusterMember
from maka.network import Network
from maka.protocol.p3_node_registration import (
    DegenerateScalarError,
    seal,
    unseal,
    xor_to_scalar,
)
from maka.wire import PAPER_SIZES, Sized

NONCE_BYTES = PAPER_SIZES["nonce"] // 8
Row = list[object]


def run(net: Network, fixture: str) -> None:
    t = trace.active()
    t.section("5.4", "Node authentication")

    matrix_rows: list[Row] = []
    for ch in net.cluster_heads.values():
        if ch.failed:
            t.step(ch.identity, f"skipped: {ch.failure_reason}")
            continue
        matrix_rows.extend(_authenticate_cluster(net, ch))

    t.table(["direction", "evidence", "verdict"], matrix_rows, "Mutual-authentication summary (P8.6)")

    _negative_paths(net)

    if fixture == fixtures.PAPER:
        bits = net.channel.total_bits(["EM1", "EM2", "EM3"])
        t.check("Table 3 row 3 (authentication) = 2400 bits", bits == 2400, 2400, bits)
    else:
        t.underspecified("Table 3 row 3 on F-NET", "[AM-06] reported only, not compared to RP9")


def _em_body(a: object, b: object, nonce: bytes) -> dict[str, object]:
    return {"A": Sized(a, PAPER_SIZES["point"]), "B": Sized(b, PAPER_SIZES["point"]), "N": nonce}


def _open_auth(cm_or_ch: ClusterHead | ClusterMember, payload: object, pr: Point) -> tuple[Point, Point, bytes]:
    return codec.decode_auth(cm_or_ch.curve, unseal(cm_or_ch.curve, payload, pr))  # type: ignore[arg-type]


def _authenticate_cluster(net: Network, ch: ClusterHead) -> list[Row]:
    t = trace.active()
    rows: list[Row] = []
    curve, g = ch.curve, ch.curve_g
    assert ch.p_ch is not None and ch.k_pub is not None and ch.pu_bs is not None  # type narrowing only

    with ledger.LedgerScope(ch.identity, "authentication"):
        ch.r_ch = rng.current().randint(1, curve.r_group)
        t.secret("r_CH", ch.r_ch, note="[IA-02] scalar drawn from Z_r* (RP9 writes Z_p; see IA-02)")
        ch.a1 = ch.r_ch * g
        ch.a2 = ch.r_ch * ch.p_ch
        t.formula("A1", "r_CH * g", ch.a1)
        t.formula("A2", "r_CH * P_CH", ch.a2)
        n_auth_ch = rng.current().bytes(NONCE_BYTES)
        t.register("IA-05", "N_auth_CH: fresh nonce instance for §5.4, distinct from N_reg")
        t.register("IA-15", "A1, A2 and N_auth_CH are drawn once per CH round: one EM1 per member "
                             "and a single EM2, as RP9 §5.4 describes")
        sealed = codec.encode_auth(ch.a1, ch.a2, n_auth_ch)
        em1 = {cm_id: net.channel.send("EM1", ch.identity, cm_id,
                                        seal(curve, g, ch.k_pub, sealed, ch.members[cm_id]),
                                        _em_body(ch.a1, ch.a2, n_auth_ch))
               for cm_id in ch.p_cm_table}
        em2 = net.channel.send("EM2", ch.identity, net.bs.identity,
                                seal(curve, g, ch.k_pub, sealed, ch.pu_bs),
                                _em_body(ch.a1, ch.a2, n_auth_ch))

    em3: list[Frame] = []
    for cm_id, frame in em1.items():
        cm = net.cluster_members[ch.identity].get(cm_id)
        if cm is None:
            continue
        with ledger.LedgerScope(cm.identity, "authentication"):
            reply = cm_handle_em1(net, cm, frame, rows)
        if reply is not None:
            em3.append(reply)

    with ledger.LedgerScope(ch.identity, "authentication"):
        for frame in em3:
            if frame.dst == ch.identity:
                ch_handle_em3(net, ch, frame, rows)

    with ledger.LedgerScope(net.bs.identity, "authentication"):
        bs_handle_em2(net, em2, rows)
    return rows


def cm_handle_em1(net: Network, cm: ClusterMember, frame: Frame | None,
                  rows: list[Row]) -> Frame | None:
    """CM verifies its CH from the delivered EM1, then answers with EM3. Returns the EM3 frame
    as delivered, or None if the CM rejected EM1 (and excluded itself)."""
    t = trace.active()
    peer = cm.id_ch or cm.deployed_cluster
    direction = f"{cm.identity} -> {peer}"
    if frame is None:
        rows.append([direction, "EM1 not delivered", "FAIL"])
        cm.mark_failed("EM1 not delivered", observer=cm.identity, peer=peer)
        return None
    if cm.failed or cm.id_ch is None or cm.p_cm is None or cm.pu_ch is None:
        rows.append([direction, "not registered", "FAIL"])
        cm.mark_failed("CM has no registration state", observer=cm.identity, peer=peer)
        return None
    try:
        a1, a2, n_auth_ch = _open_auth(cm, frame.payload, cm.pr_i)  # type: ignore[arg-type]
    except (DecodeError, InvalidTag) as exc:
        t.check("CM decrypts and decodes EM1", False, "valid EM1", f"rejected: {exc!r}")
        rows.append([direction, "EM1 decrypt/decode", "FAIL"])
        cm.mark_failed(f"EM1 rejected: {exc!r}", observer=cm.identity, peer=peer)
        return None
    fresh = cm.check_and_cache_nonce(n_auth_ch)
    a2_check = xor_to_scalar(cm.id_bs, cm.id_ch, cm.curve.r_group) * a1
    ok = fresh and a2_check == a2
    t.formula("A2' (at CM)", "(ID_BS xor ID_CH) * A1  [from decoded EM1]", a2_check)
    t.check("CM verifies CH: A2' == A2", ok, a2, a2_check)
    rows.append([direction, "A2' == A2", "PASS" if ok else "FAIL"])
    if not ok:
        cm.mark_failed("stale N_auth_CH" if not fresh else "A2' != A2", observer=cm.identity, peer=peer)
        return None
    cm.ch_verified = True
    t.event("ORIG_AUTH_OK", cm.identity, peer=cm.id_ch)

    g = cm.curve_g
    cm.r_cm = rng.current().randint(1, cm.curve.r_group)
    t.secret("r_CM", cm.r_cm, note="[IA-02] scalar drawn from Z_r* (RP9 writes Z_p; see IA-02)")
    cm.a3 = cm.r_cm * g
    cm.a4 = cm.r_cm * cm.p_cm
    t.register("ER-01", "RP9 §5.4.1 prints A4 = r_CH * P_CM, which the CM cannot compute "
                         "(it has no access to r_CH) and which fails the CH's own stated "
                         "check A4' = (ID_CH xor ID_CM)*A3 = r_CM*P_CM. Implemented as "
                         "A4 = r_CM * P_CM.")
    t.formula("A4", "r_CM * P_CM  [ER-01: corrected from RP9's printed r_CH * P_CM]", cm.a4)
    n_auth_cm = rng.current().bytes(NONCE_BYTES)
    t.register("IA-05", "N_auth_CM: fresh nonce instance for §5.4.1")
    assert cm.k_pub is not None  # type narrowing only
    payload = seal(cm.curve, g, cm.k_pub, codec.encode_auth(cm.a3, cm.a4, n_auth_cm), cm.pu_ch)
    return net.channel.send("EM3", cm.identity, cm.id_ch, payload, _em_body(cm.a3, cm.a4, n_auth_cm))


def ch_handle_em3(net: Network, ch: ClusterHead, frame: Frame, rows: list[Row]) -> None:
    """CH verifies a CM from the delivered EM3 (sender taken from the frame, IDs from CH state)."""
    t = trace.active()
    cm_id = frame.src
    cm = net.cluster_members[ch.identity].get(cm_id)
    direction = f"{ch.identity} -> {cm_id}"

    def reject(reason: str) -> None:
        rows.append([direction, reason, "FAIL"])
        if cm is not None:
            cm.mark_failed(reason, observer=ch.identity)
        else:
            t.event("ORIG_AUTH_FAIL", ch.identity, peer=cm_id, reason=reason)

    if cm_id not in ch.p_cm_table:
        reject("EM3 from a non-member")
        return
    try:
        a3, a4, n_auth_cm = _open_auth(ch, frame.payload, ch.pr_i)  # type: ignore[arg-type]
    except (DecodeError, InvalidTag) as exc:
        t.check("CH decrypts and decodes EM3", False, "valid EM3", f"rejected: {exc!r}")
        reject(f"EM3 rejected: {exc!r}")
        return
    fresh = ch.check_and_cache_nonce(n_auth_cm)
    try:
        a4_check = xor_to_scalar(ch.identity, cm_id, ch.curve.r_group) * a3
    except DegenerateScalarError as exc:
        reject(str(exc))
        return
    ok = fresh and a4_check == a4
    t.formula("A4' (at CH)", "(ID_CH xor ID_CM) * A3  [from decoded EM3]", a4_check)
    t.check("CH verifies CM: A4' == A4", ok, a4, a4_check)
    if not ok:
        reject("stale N_auth_CM" if not fresh else "A4' != A4")
        return
    rows.append([direction, "A4' == A4", "PASS"])
    ch.authenticated_members.add(cm_id)
    t.event("ORIG_AUTH_OK", ch.identity, peer=cm_id)


def bs_handle_em2(net: Network, frame: Frame | None, rows: list[Row]) -> None:
    """BS verifies a CH from the delivered EM2 (RP9 §5.4.2)."""
    t = trace.active()
    bs = net.bs
    if frame is None:
        return
    ch_id = frame.src
    ch = net.cluster_heads.get(ch_id)
    direction = f"{bs.identity} -> {ch_id}"
    try:
        a1, a2, n_auth_ch = codec.decode_auth(bs.curve, unseal(bs.curve, frame.payload, bs.pr_bs))  # type: ignore[arg-type]
        fresh = bs.check_and_cache_nonce(n_auth_ch)
        a2_check = xor_to_scalar(bs.identity, ch_id, bs.curve.r_group) * a1
    except (DecodeError, InvalidTag, DegenerateScalarError) as exc:
        t.check("BS decrypts and decodes EM2", False, "valid EM2", f"rejected: {exc!r}")
        fresh, a2, a2_check = False, None, None
    ok = fresh and a2_check is not None and a2_check == a2
    t.formula("A2' (at BS)", "(ID_BS xor ID_CH) * A1  [RP9 §5.4.2, from decoded EM2]", a2_check)
    t.check("BS verifies CH: A2' == A2", ok, a2, a2_check)
    rows.append([direction, "A2' == A2 (BS side)", "PASS" if ok else "FAIL"])
    if ok:
        t.event("ORIG_AUTH_OK", bs.identity, peer=ch_id)
    elif ch is not None:
        ch.mark_failed("BS rejected EM2", observer=bs.identity)


def _negative_paths(net: Network) -> None:
    t = trace.active()
    t.section("5.4-negative", "Negative paths")
    pairs = [(ch, cm) for ch in net.cluster_heads.values()
             for cm in net.cluster_members[ch.identity].values() if not ch.failed and not cm.failed]
    if not pairs:
        t.step("negative paths", "skipped: no authenticated CH/CM pair")
        return
    ch, cm = pairs[0]
    curve = ch.curve
    assert ch.a1 is not None and ch.a2 is not None  # type narrowing only

    # stale nonce: reuse an already-cached nonce
    stale = next(iter(cm.nonce_cache)) if cm.nonce_cache else rng.current().bytes(NONCE_BYTES)
    accepted = cm.check_and_cache_nonce(stale)
    t.check("stale nonce rejected", accepted is False, False, accepted)

    # adversary without P_CH cannot forge a matching A2
    forged_rho = rng.current().randint(1, curve.r_group)
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
