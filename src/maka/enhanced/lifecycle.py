"""Revocation, rekey, reprovisioning and designation (IMPLEMENTATION_PLAN.md §4.6.7), and the
final MAKA-E device classes.

Revoke(ID) at the BS: registry status revoked, epoch + 1, BS destroys its sessions and PSK with
ID, REVOKE_NOTICE(epoch, ID) to the affected CH (all CHs if ID is a CH); the CH destroys its
sessions/PSK with ID, removes it from the grant and ACKs. A CH that missed the notice keeps the
revoked member until its next grant refresh, which happens at every CH-BS rekey (V-LIFE-03).
Residual (documented): a revoked device's Pr stays mathematically valid; exclusion relies on
the authorisation lists, not on cryptography.
"""

from __future__ import annotations

from typing import Any

from maka import codec, hashing, ledger
from maka.codec import DecodeError
from maka.enhanced import messages as m
from maka.enhanced.data import BSData, CHData, CMData
from maka.enhanced.device import Rejected
from maka.enhanced.membership import REVOKED, RegistryEntry
from maka.runtime import device as dv
from maka.runtime.bus import Frame


class EnhancedBS(BSData):
    """The base station and provisioning authority. Its keystore alone holds k (C1)."""

    def handlers(self) -> dict[int, Any]:
        return {**super().handlers(), m.REVOKE_ACK: self._on_ack}

    # -- provisioning authority (C1, §4.6.2) ---------------------------------------------------

    def register(self, ident: str, role: str, cluster: str | None) -> None:
        self.registry[ident] = RegistryEntry(role=role, cluster=cluster, epoch=self.epoch)
        if role == dv.CH and cluster is not None and self.cluster_ch.get(cluster) is None:
            self.cluster_ch[cluster] = ident

    def provision_key(self, ident: str) -> bytes:
        """Pr_i = k * H(ID_i), computed inside the BS boundary; only this leaves (for loading
        into device i's keystore over the trusted factory channel). k never does."""
        with ledger.LedgerScope(self.identity, "provisioning"):
            k = codec.dec_scalar(self.curve, self.keystore.get("k"))
            pr = k * hashing.hash_to_point(self.curve, ident.encode())
            del k
            return codec.enc_point(pr)

    def designate(self, cluster: str, ch: str) -> list[Frame]:
        """FR-03: the operator designates `ch` (a registered CH) for `cluster`."""
        reg = self.registry.get(ch)
        if reg is None or reg.role != dv.CH or reg.status == REVOKED:
            return self.reject("UNAUTHORISED_PEER", peer=ch, reason="not an active cluster head")
        self.epoch += 1
        reg.cluster, reg.epoch = cluster, self.epoch
        self.cluster_ch[cluster] = ch
        self.emit("DESIGNATED", peer=ch, cluster=cluster, epoch=self.epoch)
        return []

    # -- revocation ----------------------------------------------------------------------------------

    def revoke(self, ident: str) -> list[Frame]:
        reg = self.registry.get(ident)
        if reg is None or reg.status == REVOKED:
            return self.reject("UNAUTHORISED_PEER", peer=ident, reason="unknown or already revoked")
        self.epoch += 1
        reg.status, reg.epoch = REVOKED, self.epoch
        self.drop_peer(ident)
        self.emit("DEVICE_REVOKED", peer=ident, role=reg.role, epoch=self.epoch)
        if reg.role == dv.CM:
            ch = self.cluster_ch.get(reg.cluster or "")
            targets = [ch] if ch is not None else []
            if ch is not None:
                self.grants.get(ch, set()).discard(ident)
        else:
            if reg.cluster is not None and self.cluster_ch.get(reg.cluster) == ident:
                self.cluster_ch[reg.cluster] = None  # its CMs' designations are now invalid
            self.grants.pop(ident, None)
            targets = [c for c, r in self.registry.items() if r.role == dv.CH and r.status != REVOKED]
        out = []
        with ledger.LedgerScope(self.identity, "lifecycle"):
            for ch in targets:
                s = self.current_session(ch, m.CH_BS)
                if s is not None:
                    out.append(self.send_to(ch, self.seal(s, m.REVOKE_NOTICE, m.encode_epoch_id(self.epoch, ident))))
        return out

    def _on_ack(self, payload: bytes, link: str) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "lifecycle"):
            _, _, pt = self.open_sealed(payload, peer=link, purpose=m.CH_BS)
            try:
                epoch, ident = m.decode_epoch_id(pt)
            except DecodeError as exc:
                raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
        self.emit("REVOKE_ACKED", peer=link, revoked=ident, epoch=epoch)
        return []


class EnhancedCH(CHData):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.notice_epoch = -1

    def handlers(self) -> dict[int, Any]:
        return {**super().handlers(), m.REVOKE_NOTICE: self._on_notice}

    def rekey(self) -> list[Frame]:
        """FR-08: new CH-BS session (supersedes the old); its claim refreshes the grant."""
        return self.start_ake(self.cfg.id_bs, m.CH_BS, fresh_budget=True)

    def _on_notice(self, payload: bytes, link: str) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "lifecycle"):
            s, _, pt = self.open_sealed(payload, peer=self.cfg.id_bs, purpose=m.CH_BS)
            try:
                epoch, ident = m.decode_epoch_id(pt)
            except DecodeError as exc:
                raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
            if not self.check("notice epoch fresh", epoch > self.notice_epoch):
                raise Rejected("REPLAY_REJECTED", peer=link, reason="stale revocation notice")
            self.notice_epoch = epoch
            closed = self.drop_peer(ident)
            self.grant.discard(ident)
            self.emit("DEVICE_REVOKED", peer=ident, sessions_closed=closed, epoch=epoch)
            ack = self.seal(s, m.REVOKE_ACK, m.encode_epoch_id(epoch, ident))
        return [self.send_to(self.cfg.id_bs, ack)]


class EnhancedCM(CMData):
    def rekey(self) -> list[Frame]:
        """FR-08 for a member: fresh CM-BS (via its CH) and CM-CH sessions."""
        out = self.start_ake(self.cfg.id_bs, m.CM_BS, self.relay_ch, fresh_budget=True)
        if self.designated is not None:
            out += self.start_ake(self.designated, m.CM_CH, fresh_budget=True)
        return out
