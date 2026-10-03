"""Data transmission, and the AM-05 aggregation halt (RP9 §5.5).

Each mutually authenticated CM encrypts a sensed reading under its k_sym (derived from
SK_CM-BS), with associated data LP(ID_CM, ID_BS, seq) and a per-sender counter nonce (IA-16),
and sends it to its CH. CMs that failed §5.4 send nothing (I-07). The CH's key inventory holds
SK_CH-BS, not SK_CM-BS. RP9 states the CH "aggregates received data" and encrypts it under
SK_CH-BS, but specifies no Aggregate operation, no plaintext-recovery path, and no envelope
format for a CH that does not hold the members' keys. This module demonstrates the gap and
halts -- no aggregation protocol is invented anywhere in this codebase (enforced by a hygiene
test).
"""

from __future__ import annotations

from maka import aead, codec, ledger, trace
from maka.network import Network
from maka.wire import Sized

READING = b"sensor-reading=21.4C"


def data_ad(src: str, dst: str, seq: int) -> bytes:
    """IA-16: the data AEAD's associated data binds sender, end-to-end recipient and seq."""
    return codec.LP(codec.enc_id(src), codec.enc_id(dst), seq.to_bytes(8, "big"))


def run(net: Network) -> None:
    t = trace.active()
    t.section("5.5-data", "Data transmission")
    t.register("IA-16", "DATA_CM: AES-256-GCM with AD = LP(ID_CM, ID_BS, seq) and nonce = "
                         "0^32 || seq, seq a per-sender counter starting at 1")
    t.register("OB-08", "seeded runs repeat keys and nonces across same-seed runs (NFR-REL-02); "
                         "they re-encrypt identical plaintexts only")

    sent = []
    for ch in net.cluster_heads.values():
        if ch.failed:
            t.step(ch.identity, f"cluster excluded from data transmission: {ch.failure_reason}")
            continue
        for cm in net.cluster_members[ch.identity].values():
            if cm.identity not in net.sym_keys:
                t.step(cm.identity, "excluded from data transmission: not authenticated (I-07)")
                continue
            with ledger.LedgerScope(cm.identity, "data"):
                seq = cm.next_seq()
                blob = aead.encrypt(net.sym_keys[cm.identity], READING,
                                    ad=data_ad(cm.identity, net.bs.identity, seq),
                                    nonce=aead.counter_nonce(seq))
                net.channel.send("DATA_CM", cm.identity, ch.identity, codec.encode_data(seq, blob),
                                  {"payload": Sized(blob, len(blob) * 8)})
                t.step(cm.identity, f"encrypts reading under SK_{{{cm.identity}-BS}}, sends to {ch.identity}")
            sent.append((ch, cm))

    if not sent:
        t.step("data", "no authenticated cluster member; nothing transmitted")
        return

    ch, cm = sent[0]
    t.step(ch.identity, "key inventory:")
    t.value(f"{ch.identity} holds SK_CH-BS", ch.identity in net.sym_keys)
    t.value(f"{ch.identity} holds SK_{cm.identity}-BS", False,
            note="CH never receives member session keys under the §5.5 key model")

    t.undefined("Aggregate",
                 "RP9 §5.5 specifies no aggregation operation and no plaintext-recovery path "
                 "for the cluster head under the stated key model (the CH holds SK_CH-BS, not "
                 "the members' SK_CM-BS it would need to read their payloads). Demonstration "
                 "halts here. See AM-05.")

    t.section("5.5-data-keycheck", "Key-material check (not a continuation of the data path)")
    for ident in (cm.identity, ch.identity):
        if ident not in net.sym_keys:
            continue
        ad = data_ad(ident, net.bs.identity, 0)
        blob2 = aead.encrypt(net.sym_keys[ident], b"round-trip-check", ad=ad)
        pt = aead.decrypt(net.bs.sym_keys[ident], blob2, ad=ad)
        t.check(f"SK_{{{ident}-BS}}: node-side encryption decrypts with the BS-side key",
                pt == b"round-trip-check", b"round-trip-check", pt)
