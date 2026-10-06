"""Generates tests/vectors/maka_e_v1.json (IMPLEMENTATION_PLAN.md §4.6.8, M4-T4).

One CM-CH AKE on `toy` parameters with a fixed seed, then the first reading CM-0101 sends
(follow-up D1/D6: DATA_CM with its hop_seq, the sealed inner frame whose nonce 0^32||seq is not
transmitted): every public value in full and, in this TEST-ONLY file, the secret intermediates too. Before writing, each value is recomputed from the
spec formulas with the pure functions in maka.enhanced.ake and checked against what the device
implementation actually sent and stored. Run once, then freeze; tests/enhanced/test_vectors.py
requires the implementation to reproduce it byte for byte.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from maka import aead, codec
from maka.enhanced import ake
from maka.enhanced import messages as m
from maka.enhanced import network as en
from maka.kdf import hmac256

SEED = 20261004
READING = "21.5C"
OUT = REPO_ROOT / "tests" / "vectors" / "maka_e_v1.json"


class Recorder:
    """Wraps a device's randomness source and records every scalar it draws."""

    def __init__(self, inner: Any) -> None:
        self.inner, self.scalars = inner, []

    def bytes(self, n: int) -> bytes:
        return self.inner.bytes(n)  # type: ignore[no-any-return]

    def randint(self, lo: int, hi: int) -> int:
        v = self.inner.randint(lo, hi)
        self.scalars.append(v)
        return v  # type: ignore[no-any-return]

    def below(self, n: int) -> int:
        return self.inner.below(n)  # type: ignore[no-any-return]

    def spawn(self, label: str) -> Any:
        return self.inner.spawn(label)


def reference_run() -> dict[str, Any]:
    net = en.build("toy", "paper", seed=SEED)
    cm, ch = net.device("CM-0101"), net.device("CH-01")
    cm.rng, ch.rng = Recorder(cm.rng), Recorder(ch.rng)  # type: ignore[assignment]
    net.onboard()
    frames = {e.frame.label: e.frame.payload for e in net.scheduler.bus.transcript
              if e.frame.src in ("CM-0101", "CH-01") and e.frame.dst in ("CM-0101", "CH-01")
              and e.frame.label in ("HS1", "HS2", "HS3")}
    curve, g = cm.curve, cm.g
    hs1, hs2, hs3 = frames["HS1"], frames["HS2"], frames["HS3"]
    h1, h2 = m.decode_hs1(hs1), m.decode_hs2(hs2)
    big_x, big_y = codec.dec_point(curve, h1.x_raw), codec.dec_point(curve, h2.y_raw)
    x = next(v for v in cm.rng.scalars if v * g == big_x)  # type: ignore[attr-defined]
    y = next(v for v in ch.rng.scalars if v * g == big_y)  # type: ignore[attr-defined]
    psk = cm.keystore.get("psk:CH-01")
    assert psk == ch.keystore.get("psk:CM-0101")
    z = x * big_y
    assert z == y * big_x
    th = hashlib.sha256(hs1 + h2.body).digest()
    keys = ake.key_schedule(psk, z, th, m.CM_CH)
    tag_r, tag_i = ake.tag_r(keys.kc_r, th), ake.tag_i(keys.kc_i, th)
    assert h2.tag == tag_r and m.decode_hs3(hs3) == (h1.sid, tag_i)
    s_cm = cm.current_session("CH-01", m.CM_CH)
    assert s_cm is not None and cm.keystore.get(s_cm.key("send")) == keys.k_ir
    assert cm.keystore.get(s_cm.key("recv")) == keys.k_ri
    data, data_secret = data_path(net)
    return {
        "description": "MAKA-E v1 test vector: one CM-CH AKE (IMPLEMENTATION_PLAN.md §4.6.8). "
                       "TEST ONLY: toy parameters are insecure, and this file contains secret "
                       "intermediates so implementations can be checked step by step.",
        "params": "toy", "topology": "paper", "seed": SEED, "initiator": "CM-0101", "responder": "CH-01",
        "purpose": m.CM_CH,
        "public": {"sid": h1.sid.hex(), "n_i": h1.n_i.hex(), "X": codec.enc_point(big_x).hex(),
                   "hs1": hs1.hex(), "n_r": h2.n_r.hex(), "Y": codec.enc_point(big_y).hex(),
                   "hs2_without_tag": h2.body.hex(), "th": th.hex(), "tag_r": tag_r.hex(), "hs2": hs2.hex(),
                   "tag_i": tag_i.hex(), "hs3": hs3.hex()},
        "secret_test_only": {"psk": psk.hex(), "x": x, "y": y, "Z": codec.enc_point(z).hex(),
                             "kc_r": keys.kc_r.hex(), "kc_i": keys.kc_i.hex(), "k_ir": keys.k_ir.hex(),
                             "k_ri": keys.k_ri.hex()},
        "data": data,
        "data_secret_test_only": data_secret,
    }


def data_path(net: en.EnhancedNetwork) -> tuple[dict[str, Any], dict[str, Any]]:
    """CM-0101's first reading: DATA_CM on the CM->CH hop, recomputed from the spec formulas."""
    cm = net.device("CM-0101")
    to_bs, hop = cm.current_session("BS-01", m.CM_BS), cm.current_session("CH-01", m.CM_CH)
    assert to_bs is not None and hop is not None
    k_cm_bs, hop_key = cm.keystore.get(to_bs.key("send")), cm.keystore.get(hop.key("hop"))
    t0 = len(net.scheduler.bus.transcript)
    net.send_reading("CM-0101", READING)
    net.run()
    data_cm = next(e.frame.payload for e in net.scheduler.bus.transcript[t0:] if e.frame.label == "DATA_CM")
    sid, hop_seq, inner, tag = m.decode_data_cm(data_cm)
    assert sid == hop.sid and hop_seq == 1
    assert tag == hmac256(hop_key, m.hop_mac_input(sid, hop_seq, inner))
    sec = m.decode_secure(inner)
    ad = m.secure_ad(sec.mtype, sec.sid, "CM-0101", "BS-01", sec.seq)
    nonce = aead.counter_nonce(sec.seq)
    assert sec.sid == to_bs.sid and len(sec.ct) == len(READING) + 16  # no nonce on the wire (D6)
    assert aead.decrypt(k_cm_bs, nonce + sec.ct, ad=ad) == READING.encode()
    assert any(r["value"] == READING for r in net.readings())
    return ({"reading": READING, "data_cm": data_cm.hex(), "sid_cm_ch": sid.hex(), "hop_seq": hop_seq,
             "inner": inner.hex(), "inner_sid_cm_bs": sec.sid.hex(), "inner_seq": sec.seq, "inner_ad": ad.hex(),
             "nonce_not_transmitted": nonce.hex(), "ciphertext_with_tag": sec.ct.hex(), "hop_tag": tag.hex()},
            {"k_cm_bs": k_cm_bs.hex(), "hop_key": hop_key.hex()})


def main() -> int:
    OUT.write_text(json.dumps(reference_run(), indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(f"wrote {OUT}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
