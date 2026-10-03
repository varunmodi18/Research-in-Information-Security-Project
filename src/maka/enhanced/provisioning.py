"""C1: provisioning without k on devices (IMPLEMENTATION_PLAN.md §4.6.2, M4-T2).

At network creation the BS draws k (system randomness on product networks) and keeps it in its
own keystore. For each device, the BS computes Pr_i = k*H(ID_i) and the factory channel loads
only Pr_i into device i's keystore. Invariant (V-CAP-01): no keystore but the BS's ever holds k.
"""

from __future__ import annotations

from collections.abc import Iterable

from maka import codec, hashing, ledger
from maka.curve import CurveParams
from maka.rng import RandomSource
from maka.runtime.device import Device
from maka.runtime.keystore import Keystore, SecretClass


class MasterKeyLeak(AssertionError):
    """V-CAP-01 violated: a non-BS keystore holds the master key."""


def new_bs_keystore(bs_id: str, curve: CurveParams, source: RandomSource) -> Keystore:
    ks = Keystore(bs_id)
    with ledger.LedgerScope(bs_id, "provisioning"):
        k = source.randint(1, curve.r_group)
        ks.put("k", codec.enc_scalar(curve, k), SecretClass.SECRET)
        ks.put("pr", codec.enc_point(k * hashing.hash_to_point(curve, bs_id.encode())), SecretClass.SECRET)
    del k
    return ks


def check_master_key_invariant(devices: Iterable[Device], bs_id: str) -> None:
    for d in devices:
        if d.identity != bs_id and d.keystore.has("k"):
            raise MasterKeyLeak(f"{d.identity} holds k")
