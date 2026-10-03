"""RP9 §6.1.7: eavesdropping resistance -- intercepted traffic fails to decrypt without the
recipient's key.

Falsifiable (IMPLEMENTATION_PLAN.md M1-T9, V-EVAL-04): the adversary intercepts a real EM1 and
a real DATA_CM frame from the channel and tries a wrong key on each; a control decryption with
the legitimate key must succeed on the same bytes. If encryption were absent or ignored the
key, the wrong-key attempt would succeed and the analysis would FAIL.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag

from maka import aead, codec, fixtures, ibe, params, rng, trace
from maka.codec import DecodeError
from maka.protocol import (
    data_transmission,
    p1_initialization,
    p2_key_generation,
    p3_node_registration,
    p4_node_authentication,
    p5_session_key_agreement,
)


def _fails(fn) -> bool:  # type: ignore[no-untyped-def]
    try:
        fn()
    except (InvalidTag, DecodeError):
        return True
    return False


def run(params_name: str = "demo") -> bool:
    t = trace.active()
    t.banner("s7_eavesdropping -- RP9 §6.1.7", "Eavesdropping resistance")
    p = params.get(params_name)
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    p4_node_authentication.run(net, fixtures.PAPER)
    p5_session_key_agreement.run(net, fixtures.PAPER)
    data_transmission.run(net)

    ch = next(iter(net.cluster_heads.values()))
    cm = next(iter(net.cluster_members[ch.identity].values()))

    em1_frames = net.channel.eavesdrop("EM1")
    data_frames = net.channel.eavesdrop("DATA_CM")
    t.step("adversary", f"intercepts {len(em1_frames)} EM1 and {len(data_frames)} DATA_CM frame(s)")
    if not em1_frames or not data_frames:
        t.check("s7_eavesdropping: real EM1 and DATA_CM frames were intercepted", False, True, False)
        return False

    em1 = codec.decode_ibe(p.curve, em1_frames[0].payload)  # type: ignore[arg-type]
    guessed_pr = rng.current().randint(1, p.curve.r_group) * cm.pu_i  # type: ignore[operator]
    auth_failed = _fails(lambda: ibe.decrypt(p.curve, em1, guessed_pr))
    auth_control = not _fails(lambda: ibe.decrypt(p.curve, em1, cm.pr_i))  # type: ignore[arg-type]
    t.check("s7 (auth): intercepted EM1 fails to decrypt without Pr_CM", auth_failed, True, auth_failed)
    t.check("s7 (auth) control: the same bytes decrypt with Pr_CM", auth_control, True, auth_control)

    frame = data_frames[0]
    seq, blob = codec.decode_data(frame.payload)  # type: ignore[arg-type]
    ad = data_transmission.data_ad(frame.src, net.bs.identity, seq)
    wrong_key = rng.current().bytes(32)
    data_failed = _fails(lambda: aead.decrypt(wrong_key, blob, ad=ad))
    plaintext = b""
    if frame.src in net.bs.sym_keys:
        try:
            plaintext = aead.decrypt(net.bs.sym_keys[frame.src], blob, ad=ad)
        except InvalidTag:
            plaintext = b""
    data_control = plaintext == data_transmission.READING
    t.check("s7 (data): intercepted DATA_CM fails to decrypt under a wrong key", data_failed, True, data_failed)
    t.check("s7 (data) control: the BS-side key recovers the reading", data_control, True, data_control)

    holds = auth_failed and auth_control and data_failed and data_control
    t.check("s7_eavesdropping HOLDS overall", holds, True, holds)
    return holds
