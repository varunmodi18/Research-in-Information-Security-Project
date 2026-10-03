"""Original-mode frame labels and RP9 §7.2 paper-model sizes.

Payload encodings are maka.codec's version-0x01 messages. Paper bits follow RP9 §7.2
(id/nonce = 160, point = 320) exactly as the legacy path does, so Table 3 reproduces (§4.7).
"""

from __future__ import annotations

from maka.wire import PAPER_SIZES

PUB_CH = "PUB_CH"
PUB_CM = "PUB_CM"
BEACON = "BEACON"
PSEUDO_BS_CH = "PSEUDO_BS_CH"
PSEUDO_CH_CM = "PSEUDO_CH_CM"
EM1 = "EM1"
EM2 = "EM2"
EM3 = "EM3"
DATA_CM = "DATA_CM"
DATA_FWD = "DATA_FWD"  # Lab-only addition to RP9: the CH forwards member ciphertexts unchanged

TABLE3_LABELS = {
    "key generation": [PUB_CH, PUB_CM],
    "registration": [BEACON, PSEUDO_BS_CH, PSEUDO_CH_CM],
    "authentication": [EM1, EM2, EM3],
}

ID, NONCE, POINT = PAPER_SIZES["id"], PAPER_SIZES["nonce"], PAPER_SIZES["point"]


def bits_pub() -> int:
    return POINT


def bits_beacon(n_members: int) -> int:
    return ID + n_members * (ID + POINT) + NONCE


def bits_pseudo_bs_ch(n_members: int) -> int:
    return POINT + n_members * POINT


def bits_pseudo_ch_cm() -> int:
    return ID + POINT  # IA-14: ID_CH added to RP9's P_CM


def bits_em() -> int:
    return POINT + POINT + NONCE
