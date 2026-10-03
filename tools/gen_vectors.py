"""Generates tests/vectors/maka_e_v1.json (IMPLEMENTATION_PLAN.md §4.6.8, M4-T4).

One CM-CH AKE on `toy` parameters with a fixed seed: every public value in full and, in this
TEST-ONLY file, the secret intermediates too. Before writing, each value is recomputed from the
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

from maka import codec
from maka.enhanced import ake
from maka.enhanced import messages as m
from maka.enhanced import network as en

SEED = 20261004
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
    }


def main() -> int:
    OUT.write_text(json.dumps(reference_run(), indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(f"wrote {OUT}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
