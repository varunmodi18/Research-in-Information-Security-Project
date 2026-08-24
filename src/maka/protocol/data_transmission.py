"""Data transmission, and the AM-05 aggregation halt (RP9 §5.5).

CM encrypts a sensed reading under SK_CM-BS, sends to the CH. The CH's key inventory holds
SK_CH-BS, not SK_CM-BS. RP9 states the CH "aggregates received data" and encrypts it under
SK_CH-BS, but specifies no Aggregate operation, no plaintext-recovery path, and no envelope
format for a CH that does not hold the members' keys. This module demonstrates the gap and
halts -- no aggregation protocol is invented anywhere in this codebase (enforced by a hygiene
test).
"""

from __future__ import annotations

from maka import aead, ledger, trace
from maka.network import Network
from maka.wire import Sized


def run(net: Network) -> None:
    t = trace.active()
    t.section("5.5-data", "Data transmission")

    ch = next(iter(net.cluster_heads.values()))
    cm = next(iter(net.cluster_members[ch.identity].values()))

    with ledger.LedgerScope(cm.identity, "data"):
        reading = b"sensor-reading=21.4C"
        blob = aead.encrypt(net.sym_keys[cm.identity], reading)
        net.channel.send("DATA_CM", cm.identity, ch.identity, blob, {"payload": Sized(blob, len(blob) * 8)})
        t.step(cm.identity, f"encrypts reading under SK_{{{cm.identity}-BS}}, sends to {ch.identity}")

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
        key = net.sym_keys[ident]
        blob2 = aead.encrypt(key, b"round-trip-check")
        pt = aead.decrypt(key, blob2)
        t.check(f"SK_{{{ident}-BS}} completes an encrypt/decrypt round trip against the BS",
                pt == b"round-trip-check", b"round-trip-check", pt)
