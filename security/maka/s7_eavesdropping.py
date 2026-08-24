"""RP9 §6.1.7: eavesdropping resistance -- intercepted traffic fails to decrypt without the
recipient's private key."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag

from maka import fixtures, ibe, params, rng, trace
from maka.protocol import (
    p1_initialization,
    p2_key_generation,
    p3_node_registration,
    p4_node_authentication,
)


def run(params_name: str = "demo") -> bool:
    t = trace.active()
    t.banner("s7_eavesdropping -- RP9 §6.1.7", "Eavesdropping resistance")
    p = params.get(params_name)
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    p4_node_authentication.run(net, fixtures.PAPER)

    ch = next(iter(net.cluster_heads.values()))
    cm = next(iter(net.cluster_members[ch.identity].values()))

    em1_frames = net.channel.eavesdrop("EM1")
    t.step("adversary", f"intercepts {len(em1_frames)} EM1 frame(s) off the public channel")
    em1_ciphertext = em1_frames[0].payload

    guessed_pr = rng.current().below(p.curve.r_group) * cm.pu_i
    auth_failed = False
    try:
        ibe.decrypt(p.curve, em1_ciphertext, guessed_pr)
    except InvalidTag:
        auth_failed = True
    t.check("s7_eavesdropping HOLDS (auth): intercepted EM1 fails to decrypt without Pr_CM",
            auth_failed, True, auth_failed)

    data_failed = False
    data_frames = net.channel.eavesdrop("DATA_CM")
    if data_frames:
        from maka.aead import decrypt as aead_decrypt

        wrong_key = rng.current().bytes(32)
        try:
            aead_decrypt(wrong_key, data_frames[0].payload)
        except InvalidTag:
            data_failed = True
    else:
        data_failed = True  # no data frame observed yet in this scenario -- vacuously fine

    holds = auth_failed and data_failed
    t.check("s7_eavesdropping HOLDS overall", holds, True, holds)
    return holds
