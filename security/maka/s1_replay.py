"""RP9 §6.1.1: replay resistance -- nonce-cache rejection."""

from __future__ import annotations

from maka import fixtures, params, rng, trace
from maka.protocol import p1_initialization, p2_key_generation, p3_node_registration


def run(params_name: str = "demo") -> bool:
    t = trace.active()
    t.banner("s1_replay -- RP9 §6.1.1", "Replay resistance via the nonce cache")
    p = params.get(params_name)
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)  # includes a replay-rejection demonstration

    t.step("RP9 §6.1.1", "each message carries a fresh nonce; a receiver rejects any message "
                          "whose nonce it has already seen, defeating replay.")
    ch = next(iter(net.cluster_heads.values()))
    stale = next(iter(net.bs.nonce_cache))
    rejected = not net.bs.check_and_cache_nonce(stale)
    t.check("s1_replay HOLDS: replayed nonce rejected", rejected, True, rejected)
    return rejected
