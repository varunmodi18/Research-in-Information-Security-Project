"""Message catalogue (Appendix B), frozen dataclasses with wire-accounting hooks.

Realises: PLAN.md P5.1. Each message type carries its paper-model bit count (RP9 §7.2's
abstraction: id/nonce = 160 bits, point = 320 bits) via `paper_bits()`, used by wire.py to
reproduce Table 3 exactly on F-PAPER.
"""

from __future__ import annotations

from dataclasses import dataclass

from maka.ibe import Ciphertext
from maka.wire import PAPER_SIZES


@dataclass(frozen=True)
class PubKeyMsg:
    """PUB_CM / PUB_CH: a bare public key, 320 bits (paper model)."""

    sender: str
    pu: object

    def paper_bits(self) -> int:
        return PAPER_SIZES["point"]


@dataclass(frozen=True)
class EncryptedMsg:
    """A message carried inside an IBE ciphertext (BEACON, EM1, EM2, EM3): its paper-model
    size is the sum of its plaintext fields' paper sizes (RP9 §7.2 does not separately cost
    the ciphertext overhead -- only the field content)."""

    label: str
    src: str
    dst: str
    ciphertext: Ciphertext
    plaintext_field_bits: int  # sum of the paper-model sizes of the encrypted fields

    def paper_bits(self) -> int:
        return self.plaintext_field_bits


@dataclass(frozen=True)
class PseudoIdMsg:
    """PSEUDO_BS_CH / PSEUDO_CH_CM: pseudo-identities sent under IA-04."""

    label: str
    src: str
    dst: str
    points: tuple[object, ...]

    def paper_bits(self) -> int:
        return PAPER_SIZES["point"] * len(self.points)


@dataclass(frozen=True)
class DataMsg:
    """DATA_CM: AEAD-encrypted sensed reading; paper-model size is not itemised by RP9
    (payload-dependent), so `paper_bits` reports the actual encoded length -- this message
    never appears in the Table 3 hard-asserted accounting."""

    src: str
    dst: str
    blob: bytes

    def paper_bits(self) -> int:
        return len(self.blob) * 8
