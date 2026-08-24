"""Shared node behaviour for ClusterHead and ClusterMember (RP9 §5.1-5.2)."""

from __future__ import annotations

from typing import ClassVar

from maka import hashing, trace
from maka.curve import CurveParams, Point
from maka.entities.base import Entity
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
        self.nonce_cache: set[bytes] = set()

    def preload(self, k_scalar: int) -> None:
        """RP9 §5.1: preloaded with (ID, p, g, k, H, ID_BS, Pu_BS)."""
        t = trace.active()
        self.k = k_scalar
        t.register("OB-01", f"{self.identity} preloaded with master key k -- held until destruction")

    def compute_keys_and_destroy_k(self) -> None:
        """RP9 §5.2: Pu_i = H(ID_i), Pr_i = k*Pu_i, then k is destroyed."""
        t = trace.active()
        assert self.k is not None, "k already destroyed -- keygen must run exactly once"
        self.pu_i = hashing.hash_to_point(self.curve, self.identity.encode())
        self.pr_i = self.k * self.pu_i
        t.formula(f"Pu_{self.identity}", "H(ID)", self.pu_i)
        t.formula(f"Pr_{self.identity}", "k * Pu", self.pr_i)
        self.k = None
        t.register("OB-01", f"{self.identity} destroys k after computing Pr_{self.identity}")
        t.check(f"{self.identity}.k destroyed", self.k is None, None, self.k)

    def check_and_cache_nonce(self, nonce: bytes) -> bool:
        t = trace.active()
        fresh = nonce not in self.nonce_cache
        self.nonce_cache.add(nonce)
        t.check(f"{self.identity} nonce freshness", True,
                 "accept" if fresh else "reject (replay)", "accept" if fresh else "reject (replay)")
        return fresh
