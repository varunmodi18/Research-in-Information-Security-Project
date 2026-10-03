"""BaseStation: RP9 §5.1-5.2, 5.3(BS side), 5.4.2, 5.5 responsibilities."""

from __future__ import annotations

from typing import ClassVar

from maka import hashing, trace
from maka.curve import CurveParams, Point
from maka.entities.base import Entity
from maka.wire import PAPER_SIZES


class BaseStation(Entity):
    STORAGE_FIELDS: ClassVar[list[tuple[str, int]]] = [
        ("id_bs", PAPER_SIZES["id"]),
        ("g", PAPER_SIZES["point"]),
        ("k", PAPER_SIZES["point"]),  # destroyed after key generation (OB-01)
        ("pu_bs", PAPER_SIZES["point"]),
        ("pr_bs", PAPER_SIZES["point"]),
        ("k_pub", PAPER_SIZES["point"]),  # [IA-03 scaffolding]
    ]

    def __init__(self, identity: str, curve: CurveParams, g: Point) -> None:
        super().__init__(identity)
        self.curve = curve
        self.g = g
        self.id_bs = identity
        self.k: int | None = None
        self.pu_bs: Point | None = None
        self.pr_bs: Point | None = None
        self.k_pub: Point | None = None
        self.nonce_cache: set[bytes] = set()
        self.session_keys: dict[str, object] = {}
        # Registration state, built only from decoded BEACON contents (I-03):
        # ID_CH -> {ID_CM: Pu_CM}, and the pseudo-identities computed from them.
        self.clusters: dict[str, dict[str, Point]] = {}
        self.pseudo_ids: dict[str, Point] = {}
        self.ch_public_keys: dict[str, Point] = {}  # from decoded PUB_CH frames
        self.sym_keys: dict[str, bytes] = {}  # BS-side k_sym per node, from P5
        self.last_seq: dict[str, int] = {}  # highest accepted DATA_CM seq per sender

    def public_key_of(self, ident: str) -> Point | None:
        """Pu_i as the BS learned it from decoded frames: PUB_CH for CHs, BEACON for CMs."""
        if ident in self.ch_public_keys:
            return self.ch_public_keys[ident]
        for members in self.clusters.values():
            if ident in members:
                return members[ident]
        return None

    def generate_parameters(self, k_scalar: int) -> None:
        """RP9 §5.1: computes Pu_BS = H(ID_BS), Pr_BS = k*Pu_BS. Publishes K_pub = k*g,
        scaffolding for IA-03's IBE instantiation, never described as an RP9 parameter."""
        t = trace.active()
        self.k = k_scalar
        self.pu_bs = hashing.hash_to_point(self.curve, self.id_bs.encode())
        self.pr_bs = k_scalar * self.pu_bs
        self.k_pub = k_scalar * self.g
        t.formula("Pu_BS", "H(ID_BS)", self.pu_bs)
        t.secret("Pr_BS", self.pr_bs, note="= k * Pu_BS")
        t.value("K_pub", self.k_pub, note="[IA-03 scaffolding -- not part of RP9's parameter set]")

    def destroy_master_key(self) -> None:
        """Deletes the `k` attribute. Python ints cannot be overwritten in place, so the value
        remains in process memory until garbage-collected (see Node.compute_keys_and_destroy_k)."""
        t = trace.active()
        t.register("OB-01", f"{self.identity} deletes the master key k after key generation")
        if hasattr(self, "k"):
            del self.k
        gone = not hasattr(self, "k")
        t.check("k deleted (attribute no longer exists)", gone, True, gone)

    def check_and_cache_nonce(self, nonce: bytes) -> bool:
        """Returns True if fresh (accepted), False if a replay (rejected)."""
        t = trace.active()
        fresh = nonce not in self.nonce_cache
        self.nonce_cache.add(nonce)
        t.check(f"nonce freshness ({'hit' if not fresh else 'miss'})", True,
                 "accept" if fresh else "reject (replay)", "accept" if fresh else "reject (replay)")
        return fresh
