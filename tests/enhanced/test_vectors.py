"""M4-T4 / §4.6.8: the implementation reproduces tests/vectors/maka_e_v1.json byte for byte, and
the vector itself satisfies the spec equations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from maka import codec, params
from maka.enhanced import ake
from maka.enhanced import messages as m
from maka.enhanced import network as en

VECTOR = json.loads((Path(__file__).parent.parent / "vectors" / "maka_e_v1.json").read_text(encoding="utf-8"))


def test_vector_satisfies_spec_equations() -> None:
    curve, g = params.get("toy").curve, params.get("toy").g
    pub, sec = VECTOR["public"], VECTOR["secret_test_only"]
    x_pt, y_pt = codec.dec_point(curve, bytes.fromhex(pub["X"])), codec.dec_point(curve, bytes.fromhex(pub["Y"]))
    assert sec["x"] * g == x_pt and sec["y"] * g == y_pt
    assert codec.enc_point(sec["x"] * y_pt).hex() == sec["Z"] == codec.enc_point(sec["y"] * x_pt).hex()
    hs1, body = bytes.fromhex(pub["hs1"]), bytes.fromhex(pub["hs2_without_tag"])
    th = hashlib.sha256(hs1 + body).digest()
    assert th.hex() == pub["th"]
    keys = ake.key_schedule(bytes.fromhex(sec["psk"]), sec["x"] * y_pt, th, VECTOR["purpose"])
    assert [keys.kc_r.hex(), keys.kc_i.hex(), keys.k_ir.hex(), keys.k_ri.hex()] == [
        sec["kc_r"], sec["kc_i"], sec["k_ir"], sec["k_ri"]]
    assert ake.tag_r(keys.kc_r, th).hex() == pub["tag_r"] and ake.tag_i(keys.kc_i, th).hex() == pub["tag_i"]
    assert pub["hs2"] == pub["hs2_without_tag"] + pub["tag_r"]


def test_implementation_reproduces_vector() -> None:
    net = en.build(VECTOR["params"], VECTOR["topology"], seed=VECTOR["seed"])
    net.onboard()
    pub = VECTOR["public"]
    sent = {e.frame.label: e.frame.payload.hex() for e in net.scheduler.bus.transcript
            if e.frame.label in ("HS1", "HS2", "HS3") and {e.frame.src, e.frame.dst} == {"CM-0101", "CH-01"}
            and (e.frame.label != "HS2" or m.decode_hs2(e.frame.payload).id_r == "CH-01")}
    assert sent == {"HS1": pub["hs1"], "HS2": pub["hs2"], "HS3": pub["hs3"]}
    cm = net.device("CM-0101")
    s = cm.current_session("CH-01", m.CM_CH)
    assert cm.keystore.get(s.key("send")).hex() == VECTOR["secret_test_only"]["k_ir"]
    assert cm.keystore.get("psk:CH-01").hex() == VECTOR["secret_test_only"]["psk"]
