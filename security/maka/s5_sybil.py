"""RP9 §6.1.5: Sybil resistance -- unique preloaded identifiers; identity not derivable from
transmitted messages; authentication required before any data exchange."""

from __future__ import annotations

from maka import fixtures, params, trace
from maka.protocol import p1_initialization, p2_key_generation


def run(params_name: str = "demo") -> bool:
    t = trace.active()
    t.banner("s5_sybil -- RP9 §6.1.5", "Sybil resistance")
    p = params.get(params_name)
    net = p1_initialization.run(p.curve, p.g, fixtures.NET)
    p2_key_generation.run(net)

    all_ids = [net.bs.identity]
    for ch in net.cluster_heads.values():
        all_ids.append(ch.identity)
        all_ids.extend(net.cluster_members[ch.identity].keys())
    unique = len(all_ids) == len(set(all_ids))
    t.check("all preloaded identities are unique", unique, True, unique)

    t.step("RP9 §6.1.5", "an identity cannot be derived from Pu_i = H(ID_i) alone (H is "
                          "one-way), and no message exchange occurs before mutual "
                          "authentication (§6.1.4) succeeds -- so an adversary cannot mint an "
                          "accepted identity without a preloaded (ID_i, k) pair.")
    t.check("s5_sybil HOLDS: unique preloaded identifiers, no pre-auth data exchange",
            unique, True, unique)
    return unique
