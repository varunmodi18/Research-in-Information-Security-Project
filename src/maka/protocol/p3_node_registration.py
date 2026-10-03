"""RP9 §5.3: node registration.

CH collects its members' public keys from the PUB_CM frames it received (I-04), assembles the
beacon (ID_CH, [ID_CM...], [Pu_CM...], N_reg), encrypts it under Pu_BS and sends it. The BS
decrypts and decodes the *delivered* beacon (I-03), checks N_reg against its nonce cache,
computes P_CH = (ID_BS xor ID_CH)*g and P_CM = (ID_CH xor ID_CM)*g from the decoded IDs, and
sends (P_CH, P_CM...) to the CH. The CH forwards each P_CM, with ID_CH (IA-14), to its member.

Applies: IA-05 (N_reg is the registration-nonce instance), IA-04 ('sent securely': IBE to the
recipient when `secure_pseudo_ids` is on, I-02), IA-13 (fixed 160-bit ID fields, I-05),
AM-06/F-PAPER (Table 3 row 2 hard assertion only on F-PAPER).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag

from maka import codec, fixtures, hashing, ibe, ledger, rng, trace
from maka.channel import Frame
from maka.codec import DecodeError
from maka.curve import CurveParams, Point
from maka.entities.cluster_head import ClusterHead
from maka.entities.cluster_member import ClusterMember
from maka.network import Network
from maka.wire import PAPER_SIZES, Sized

NONCE_BYTES = PAPER_SIZES["nonce"] // 8
PUBLISHED_ROW2 = 1760  # RP9 Table 3 row 2 (registration), F-PAPER
ID_CH_BITS = PAPER_SIZES["id"]  # IA-14: ID_CH added to each PSEUDO_CH_CM


class DegenerateScalarError(ValueError):
    """(ID_a xor ID_b) reduces to 0 in Z_r_group, so the pseudo-identity would be the point at
    infinity and every authentication check against it would pass vacuously (I-05)."""


def xor_to_scalar(id_a: str, id_b: str, r_group: int) -> int:
    """(ID_a xor ID_b) as RP9 writes it, reduced into Z_r_group (IA-02).

    Each identifier is placed in a fixed 160-bit field, left-aligned and zero-padded (IA-13),
    so the XOR is taken over RP9 §7.2's 160-bit identifiers rather than over variable-length
    integers. A zero result raises DegenerateScalarError."""
    a = codec.id_field(id_a)
    b = codec.id_field(id_b)
    scalar = int.from_bytes(bytes(x ^ y for x, y in zip(a, b)), "big") % r_group
    if scalar == 0:
        raise DegenerateScalarError(f"({id_a} xor {id_b}) mod r_group = 0")
    return scalar


def seal(curve: CurveParams, g: Point, k_pub: Point, plaintext: bytes, recipient_pu: Point) -> bytes:
    """Enc(plaintext, Pu_recipient) under IA-03, encoded as frame payload."""
    return codec.encode_ibe(ibe.encrypt(curve, g, plaintext, recipient_pu, k_pub))


def unseal(curve: CurveParams, payload: bytes, recipient_pr: Point) -> bytes:
    """Decodes and decrypts an IBE frame payload. Raises DecodeError or InvalidTag."""
    return ibe.decrypt(curve, codec.decode_ibe(curve, payload), recipient_pr)


def run(net: Network, fixture: str, secure_pseudo_ids: bool | None = None) -> None:
    t = trace.active()
    t.section("5.3", "Node registration")
    if secure_pseudo_ids is not None:
        net.secure_pseudo_ids = secure_pseudo_ids
    if net.secure_pseudo_ids:
        t.register("IA-04", "'sent securely' instantiated as IBE encryption to the recipient's "
                             "public key: PSEUDO_BS_CH under H(ID_CH), PSEUDO_CH_CM under Pu_CM.")
        t.register("OB-07", "RP9 Table 2 does not price secure pseudo-identity delivery: it adds "
                             "n+1 T_E/D at the CH, 1 at each CM, and 1 T_E/D + 1 T_HG at the BS. "
                             "Paper-table reproduction runs with --no-secure-pseudo-ids.")
    else:
        t.register("IA-04", "--no-secure-pseudo-ids: pseudo-identities sent in clear (paper-table "
                             "reproduction mode; RP9 Table 2 prices no encryption for them).")

    t.register("IA-12", "frames are maka.codec encodings; every decoded point is validated "
                         "(on-curve, not infinity, r*P = O), priced as T_SM_val")
    t.register("IA-13", "IDs occupy fixed 160-bit fields for ID_a xor ID_b; a zero scalar is rejected")
    _bs_learn_ch_keys(net)
    t.register("IA-14", f"PSEUDO_CH_CM carries ID_CH (+{ID_CH_BITS} bits per member) so the CM "
                         "learns which CH it verifies against; Table 3 row 2 is therefore "
                         f"{PUBLISHED_ROW2} + {ID_CH_BITS}*n bits")
    for ch in net.cluster_heads.values():
        _register_cluster(net, ch)

    if fixture == fixtures.PAPER:
        n = sum(len(m) for m in net.cluster_members.values())
        beacon_bits = net.channel.total_bits(["BEACON"])
        pseudo_bs_ch_bits = net.channel.total_bits(["PSEUDO_BS_CH"])
        pseudo_ch_cm_bits = net.channel.total_bits(["PSEUDO_CH_CM"])
        total = beacon_bits + pseudo_bs_ch_bits + pseudo_ch_cm_bits
        t.check(f"Table 3 row 2 (registration) = {PUBLISHED_ROW2} + {ID_CH_BITS}*{n} bits [IA-14]",
                total == PUBLISHED_ROW2 + ID_CH_BITS * n, PUBLISHED_ROW2 + ID_CH_BITS * n, total)
        t.check("BEACON = 800 bits", beacon_bits == 800, 800, beacon_bits)
        t.check("BS->CH (PSEUDO_BS_CH) = 640 bits", pseudo_bs_ch_bits == 640, 640, pseudo_bs_ch_bits)
        t.check(f"CH->CM (PSEUDO_CH_CM) = 320 + {ID_CH_BITS} bits [IA-14]",
                pseudo_ch_cm_bits == 320 + ID_CH_BITS * n, 320 + ID_CH_BITS * n, pseudo_ch_cm_bits)
    else:
        t.underspecified("Table 3 row 2 on F-NET",
                          "[AM-06] RP9 never states the topology its cost tables assume; "
                          "F-NET's totals are reported only, never compared against RP9's tables")
        t.value("F-NET registration bits (reported only)",
                net.channel.total_bits(["BEACON", "PSEUDO_BS_CH", "PSEUDO_CH_CM"]))


def _bs_learn_ch_keys(net: Network) -> None:
    """The BS decodes the PUB_CH frames delivered to it (used later for SK_BS-CH, §5.5)."""
    t = trace.active()
    with ledger.LedgerScope(net.bs.identity, "registration"):
        for frame in net.channel.inbox(net.bs.identity, "PUB_CH"):
            try:
                net.bs.ch_public_keys[frame.src] = codec.decode_pub(net.bs.curve, frame.payload)  # type: ignore[arg-type]
            except DecodeError as exc:
                t.event("DECODE_ERROR", net.bs.identity, frame="PUB_CH", src=frame.src, reason=str(exc))


def _register_cluster(net: Network, ch: ClusterHead) -> None:
    t = trace.active()
    curve = ch.curve
    assert ch.pu_bs is not None and ch.k_pub is not None  # type narrowing only

    with ledger.LedgerScope(ch.identity, "registration"):
        for frame in net.channel.inbox(ch.identity, "PUB_CM"):
            try:
                ch.add_member(frame.src, codec.decode_pub(curve, frame.payload))  # type: ignore[arg-type]
            except DecodeError as exc:
                t.event("DECODE_ERROR", ch.identity, frame="PUB_CM", src=frame.src, reason=str(exc))
        member_ids = list(ch.members)
        n_reg = rng.current().bytes(NONCE_BYTES)
        t.step(ch.identity, "assembling beacon (ID_CH, [ID_CM...], [Pu_CM...], N_reg) from received PUB_CM frames")
        beacon = codec.encode_beacon(ch.identity, list(ch.members.items()), n_reg)
        body = {
            "ID_CH": Sized(ch.identity, PAPER_SIZES["id"]),
            "ID_CM(s)": Sized(member_ids, PAPER_SIZES["id"] * len(member_ids)),
            "Pu_CM(s)": Sized(list(ch.members.values()), PAPER_SIZES["point"] * len(member_ids)),
            "N_reg": n_reg,
        }
        beacon_frame = net.channel.send("BEACON", ch.identity, net.bs.identity,
                                         seal(curve, ch.curve_g, ch.k_pub, beacon, ch.pu_bs), body)

    if beacon_frame is None:
        ch.mark_failed("BEACON not delivered", observer=net.bs.identity)
        return
    with ledger.LedgerScope(net.bs.identity, "registration"):
        result = bs_receive_beacon(net, beacon_frame)
    if result is None:
        ch.mark_failed("BS rejected the BEACON", observer=net.bs.identity)
        return
    id_ch, p_ch, p_cms = result

    with ledger.LedgerScope(net.bs.identity, "registration"):
        plaintext = codec.encode_pseudo_bs_ch(p_ch, p_cms)
        if net.secure_pseudo_ids:
            payload = seal(curve, net.bs.g, net.bs.k_pub, plaintext,  # type: ignore[arg-type]
                           hashing.hash_to_point(curve, id_ch.encode()))
        else:
            payload = plaintext
        pseudo_frame = net.channel.send(
            "PSEUDO_BS_CH", net.bs.identity, id_ch, payload,
            {"P_CH": Sized(p_ch, PAPER_SIZES["point"]),
             "P_CM(s)": Sized(p_cms, PAPER_SIZES["point"] * len(p_cms))})

    deliveries: list[tuple[str, Frame | None]] = []
    with ledger.LedgerScope(ch.identity, "registration"):
        if pseudo_frame is None or pseudo_frame.dst != ch.identity:
            ch.mark_failed("PSEUDO_BS_CH not delivered", observer=ch.identity, peer=net.bs.identity)
            return
        try:
            raw = (unseal(curve, pseudo_frame.payload, ch.pr_i)  # type: ignore[arg-type]
                   if net.secure_pseudo_ids else pseudo_frame.payload)
            ch.p_ch, decoded_p_cms = codec.decode_pseudo_bs_ch(curve, raw)  # type: ignore[arg-type]
            if len(decoded_p_cms) != len(member_ids):
                raise DecodeError("P_CM count differs from the beacon's member count")
        except (DecodeError, InvalidTag) as exc:
            ch.mark_failed(f"PSEUDO_BS_CH rejected: {exc}", observer=ch.identity, peer=net.bs.identity)
            return
        ch.p_cm_table = dict(zip(member_ids, decoded_p_cms))
        for cm_id, p_cm in ch.p_cm_table.items():
            plaintext = codec.encode_pseudo_ch_cm(ch.identity, p_cm)
            payload = (seal(curve, ch.curve_g, ch.k_pub, plaintext, ch.members[cm_id])
                       if net.secure_pseudo_ids else plaintext)
            deliveries.append((cm_id, net.channel.send(
                "PSEUDO_CH_CM", ch.identity, cm_id, payload,
                {"ID_CH": Sized(ch.identity, ID_CH_BITS), "P_CM": Sized(p_cm, PAPER_SIZES["point"])})))

    for cm_id, frame in deliveries:
        cm = net.cluster_members[ch.identity].get(cm_id)
        if cm is None:
            continue  # the beacon named an ID no simulated device answers to
        with ledger.LedgerScope(cm.identity, "registration"):
            cm_receive_pseudo(net, cm, frame)

    _demonstrate_replay_rejection(net, beacon_frame)


def bs_receive_beacon(net: Network, frame: Frame) -> tuple[str, Point, list[Point]] | None:
    """BS side of §5.3, from the delivered bytes only. Returns (ID_CH, P_CH, [P_CM...]) or None."""
    t = trace.active()
    bs = net.bs
    curve = bs.curve
    try:
        beacon = codec.decode_beacon(curve, unseal(curve, frame.payload, bs.pr_bs))  # type: ignore[arg-type]
    except (DecodeError, InvalidTag) as exc:
        t.event("DECODE_ERROR", bs.identity, frame="BEACON", src=frame.src, reason=str(exc))
        return None
    if not bs.check_and_cache_nonce(beacon.n_reg):
        t.event("REPLAY_REJECTED", bs.identity, frame="BEACON", src=frame.src)
        return None
    try:
        p_ch = xor_to_scalar(bs.identity, beacon.id_ch, curve.r_group) * bs.g
        p_cms = [xor_to_scalar(beacon.id_ch, cm_id, curve.r_group) * bs.g for cm_id, _ in beacon.members]
    except DegenerateScalarError as exc:
        t.event("DEGENERATE_SCALAR", bs.identity, frame="BEACON", src=frame.src, reason=str(exc))
        return None
    t.formula("P_CH", f"(ID_BS xor {beacon.id_ch}) * g", p_ch)
    for (cm_id, _), p_cm in zip(beacon.members, p_cms):
        t.formula(f"P_{cm_id}", f"({beacon.id_ch} xor {cm_id}) * g", p_cm)
        bs.pseudo_ids[cm_id] = p_cm
    bs.pseudo_ids[beacon.id_ch] = p_ch
    bs.clusters[beacon.id_ch] = dict(beacon.members)
    return beacon.id_ch, p_ch, p_cms


def cm_receive_pseudo(net: Network, cm: ClusterMember, frame: Frame | None) -> None:
    """CM side: learn ID_CH and P_CM from the delivered PSEUDO_CH_CM, and Pu_CH from the CH's
    overheard PUB_CH broadcast (IA-08)."""
    curve = cm.curve
    if frame is None:
        cm.mark_failed("PSEUDO_CH_CM not delivered", observer=cm.identity, peer=cm.deployed_cluster)
        return
    try:
        raw = unseal(curve, frame.payload, cm.pr_i) if net.secure_pseudo_ids else frame.payload  # type: ignore[arg-type]
        id_ch, p_cm = codec.decode_pseudo_ch_cm(curve, raw)  # type: ignore[arg-type]
        pub = [f for f in net.channel.eavesdrop("PUB_CH") if f.src == id_ch]
        if not pub:
            raise DecodeError(f"no PUB_CH broadcast from {id_ch} was overheard")
        pu_ch = codec.decode_pub(curve, pub[-1].payload)  # type: ignore[arg-type]
    except (DecodeError, InvalidTag) as exc:
        cm.mark_failed(f"PSEUDO_CH_CM rejected: {exc}", observer=cm.identity, peer=frame.src)
        return
    cm.id_ch, cm.p_cm, cm.pu_ch = id_ch, p_cm, pu_ch


def _demonstrate_replay_rejection(net: Network, beacon_frame: Frame) -> None:
    """The adversary re-injects the captured BEACON; the BS processes the replayed bytes."""
    t = trace.active()
    t.step("adversary", f"replaying the {beacon_frame.src} BEACON frame")
    replayed = net.channel.replay(beacon_frame)
    with ledger.LedgerScope(net.bs.identity, "replay-demo"):
        accepted = bs_receive_beacon(net, replayed) is not None
    t.check("replayed BEACON is rejected", accepted is False, False, accepted)
