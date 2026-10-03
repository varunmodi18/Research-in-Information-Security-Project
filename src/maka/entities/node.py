"""Shared node behaviour for ClusterHead and ClusterMember (RP9 §5.1-5.2)."""

from __future__ import annotations

from typing import ClassVar

from maka import hashing, trace
from maka.curve import CurveParams, Point
from maka.entities.base import Entity, ProtocolError
from maka.wire import PAPER_SIZES


class Node(Entity):
    STORAGE_FIELDS: ClassVar[list[tuple[str, int]]] = [
        ("identity_field", PAPER_SIZES["id"]),
        ("curve_g", PAPER_SIZES["point"]),
        ("k", PAPER_SIZES["point"]),  # destroyed after key generation (OB-01)
        ("id_bs", PAPER_SIZES["id"]),
        ("pu_bs", PAPER_SIZES["point"]),
        ("pu_i", PAPER_SIZES["point"]),
        ("pr_i", PAPER_SIZES["point"]),
    ]

    def __init__(self, identity: str, curve: CurveParams, g: Point, id_bs: str, pu_bs: Point) -> None:
        super().__init__(identity)
        self.curve = curve
        self.curve_g = g
        self.identity_field = identity
        self.id_bs = id_bs
        self.pu_bs = pu_bs
        self.k: int | None = None
        self.pu_i: Point | None = None
        self.pr_i: Point | None = None
        self.k_pub: Point | None = None  # [IA-03 scaffolding] public IBE parameter K_pub = k*g
        self.nonce_cache: set[bytes] = set()
        self.data_seq = 0  # per-sender DATA_CM counter (IA-16)

    def preload(self, k_scalar: int, k_pub: Point) -> None:
        """RP9 §5.1: preloaded with (ID, p, g, k, H, ID_BS, Pu_BS), plus the IBE public
        parameter K_pub that IA-03's Enc needs (scaffolding, not an RP9 parameter)."""
        t = trace.active()
        self.k = k_scalar
        self.k_pub = k_pub
        t.register("OB-01", f"{self.identity} preloaded with master key k -- held until destruction")

    def compute_keys_and_destroy_k(self) -> None:
        """RP9 §5.2: Pu_i = H(ID_i), Pr_i = k*Pu_i, then k is destroyed.

        "Destroyed" means the attribute is deleted, so no reference to the integer remains on
        this object. Python ints are immutable and cannot be overwritten in place; the value
        stays in process memory until garbage-collected. This is a demonstration limitation,
        not a zeroisation guarantee."""
        t = trace.active()
        k_scalar = getattr(self, "k", None)
        if k_scalar is None:
            raise ProtocolError(f"{self.identity}: k already destroyed -- keygen must run exactly once")
        self.pu_i = hashing.hash_to_point(self.curve, self.identity.encode())
        self.pr_i = k_scalar * self.pu_i
        t.formula(f"Pu_{self.identity}", "H(ID)", self.pu_i)
        t.secret(f"Pr_{self.identity}", self.pr_i, note="= k * Pu")
        del self.k
        del k_scalar
        t.register("OB-01", f"{self.identity} deletes k after computing Pr_{self.identity}")
        gone = not hasattr(self, "k")
        t.check(f"{self.identity}.k deleted (attribute no longer exists)", gone, True, gone)

    def next_seq(self) -> int:
        self.data_seq += 1
        return self.data_seq

    def check_and_cache_nonce(self, nonce: bytes) -> bool:
        t = trace.active()
        fresh = nonce not in self.nonce_cache
        self.nonce_cache.add(nonce)
        t.check(f"{self.identity} nonce freshness", True,
                 "accept" if fresh else "reject (replay)", "accept" if fresh else "reject (replay)")
        return fresh
