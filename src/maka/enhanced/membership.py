"""C4: BS-authorised membership, designation and the relay (IMPLEMENTATION_PLAN.md §4.6.5).

Onboarding, per cluster:
 1 CH-BS AKE.  2 CH -> BS CLUSTER_CLAIM (member IDs from the CH's provisioning configuration).
 3 BS checks each ID against its registry -> CLUSTER_GRANT(epoch, granted, rejected);
   CLAIM_REJECTED per rejected ID.  The CH sends CLUSTER_OPEN to each granted member.
 4 CM-BS AKE, relayed unchanged by the CH (envelope V||0x30||LP(final_dst, inner)).
 5 BS -> CM DESIGNATION(epoch, ID_CH) over the CM-BS session.
 6 CM-CH AKE: the CM refuses a non-designated CH; the CH refuses CMs outside its grant.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from maka import ledger
from maka.codec import DecodeError
from maka.enhanced import messages as m
from maka.enhanced.device import EnhancedDevice, Rejected, guarded
from maka.enhanced.states import Session
from maka.runtime import device as dv
from maka.runtime.bus import Frame
from maka.runtime.device import BACKGROUND

REVOKED = "revoked"
GRANT_REFRESH = BACKGROUND + "grant_refresh"


@dataclass
class RegistryEntry:
    role: str
    cluster: str | None
    status: str = "provisioned"  # provisioned | revoked
    epoch: int = 0


class BSMembership(EnhancedDevice):
    role = dv.BS

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.registry: dict[str, RegistryEntry] = {}
        self.cluster_ch: dict[str, str | None] = {}  # cluster label -> its designated CH
        self.grants: dict[str, set[str]] = {}  # CH -> granted members
        self.epoch = 0
        self.status = dv.ACTIVE

    def handlers(self) -> dict[int, Any]:
        return {**super().handlers(), m.RELAY: self._on_relay, m.CLUSTER_CLAIM: self._on_claim}

    def registry_epoch(self) -> int:
        return self.epoch

    def _on_relay(self, payload: bytes, link: str) -> list[Frame]:
        try:
            final_dst, inner = m.decode_relay(payload)
        except DecodeError as exc:
            raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
        if final_dst != self.identity:
            raise Rejected("WRONG_RECIPIENT", peer=link)
        return self.dispatch(inner, link)

    # responder policy (§4.6.4 steps 3-4) -----------------------------------------------------

    def purpose_ok(self, id_i: str, purpose: str) -> bool:
        want = {m.CH_BS: dv.CH, m.CM_BS: dv.CM}.get(purpose)
        reg = self.registry.get(id_i)
        return want is not None and (reg is None or reg.role == want)

    def authorised(self, id_i: str, purpose: str) -> bool:
        reg = self.registry.get(id_i)
        return reg is not None and reg.status != REVOKED

    def on_established(self, s: Session) -> list[Frame]:
        if s.purpose == m.CM_BS:
            reg = self.registry[s.peer]
            ch = self.cluster_ch.get(reg.cluster or "")
            if ch is None:
                return []
            with ledger.LedgerScope(self.identity, "membership"):
                sealed = self.seal(s, m.DESIGNATION, m.encode_epoch_id(self.epoch, ch))
            return [self.send_to(s.peer, sealed, s.via)]
        return []

    def _on_claim(self, payload: bytes, link: str) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "membership"):
            s, _, pt = self.open_sealed(payload, peer=link, purpose=m.CH_BS)
            try:
                claimed = m.dec_ids(pt)
            except DecodeError as exc:
                raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
            ch_reg = self.registry.get(link)
            granted: list[str] = []
            rejected: list[str] = []
            for cm in claimed:
                reg = self.registry.get(cm)
                ok = (reg is not None and reg.role == dv.CM and reg.status != REVOKED and ch_reg is not None
                      and reg.cluster == ch_reg.cluster and self.cluster_ch.get(ch_reg.cluster or "") == link)
                (granted if ok else rejected).append(cm)
            for cm in rejected:
                self.emit("CLAIM_REJECTED", peer=cm, ch=link)
            self.grants[link] = set(granted)
            self.emit("GRANT_ISSUED", peer=link, granted=len(granted), rejected=len(rejected), epoch=self.epoch)
            sealed = self.seal(s, m.CLUSTER_GRANT, m.encode_grant(self.epoch, granted, rejected))
        return [self.send_to(link, sealed)]


class CHMembership(EnhancedDevice):
    role = dv.CH

    def __init__(self, *args: Any, member_config: list[str], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.member_config = list(member_config)  # provisioning config: "local discovery"
        self.grant: set[str] = set()
        self.grant_epoch = -1
        self._timer_claims = 0  # claims sent by the refresh timer whose grant has not arrived yet

    def handlers(self) -> dict[int, Any]:
        return {**super().handlers(), m.RELAY: self._on_relay, m.CLUSTER_GRANT: self._on_grant}

    def start_onboarding(self) -> list[Frame]:
        return self.start_ake(self.cfg.id_bs, m.CH_BS, fresh_budget=True)

    @guarded
    def refresh_grant(self) -> list[Frame]:
        """Re-requests CLUSTER_GRANT over the current CH-BS session (§4.6.7 recovery): after every
        CH-BS handshake and every grant_refresh_steps steps (follow-up D3, docs/PLAN_ERRATA.md E-09)."""
        s = self.current_session(self.cfg.id_bs, m.CH_BS)
        if s is None:
            return self.start_onboarding()
        with ledger.LedgerScope(self.identity, "membership"):
            return [self.send_to(self.cfg.id_bs, self.seal(s, m.CLUSTER_CLAIM, m.enc_ids(self.member_config)))]

    def purpose_ok(self, id_i: str, purpose: str) -> bool:
        return purpose == m.CM_CH

    def authorised(self, id_i: str, purpose: str) -> bool:
        return id_i in self.grant

    def on_established(self, s: Session) -> list[Frame]:
        if s.purpose == m.CH_BS:
            if self.status == dv.PROVISIONED:
                self.set_status(dv.REGISTERED)
            return self.refresh_grant()  # a claim after every CH-BS handshake (incl. rekey)
        return []

    def _on_grant(self, payload: bytes, link: str) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "membership"):
            s, _, pt = self.open_sealed(payload, peer=self.cfg.id_bs, purpose=m.CH_BS)
            try:
                epoch, granted, _rejected = m.decode_grant(pt)
            except DecodeError as exc:
                raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
        if not self.check("grant epoch not stale", epoch >= self.grant_epoch):
            raise Rejected("REPLAY_REJECTED", peer=link, reason="stale grant epoch")
        self.learn_epoch(epoch, s)
        for gone in self.grant - set(granted):
            self.drop_peer(gone)
        # A grant answering a timer refresh opens only members new to the grant: re-opening the
        # others could restart a member's onboarding that is still under way (follow-up D3).
        periodic, self._timer_claims = self._timer_claims > 0, max(0, self._timer_claims - 1)
        previous = self.grant
        self.grant, self.grant_epoch = set(granted), epoch
        self.set_status(dv.ACTIVE)
        self.set_timer(GRANT_REFRESH, self.cfg.grant_refresh_steps)
        return [self.frame(cm, "CLUSTER_OPEN", m.encode_open(self.identity, epoch))
                for cm in granted if self.current_session(cm, m.CM_CH) is None
                and not (periodic and cm in previous)]

    def on_role_timer(self, name: str) -> list[Frame]:
        if name == GRANT_REFRESH:
            out = self.refresh_grant()
            if any(f.label == "CLUSTER_CLAIM" for f in out):
                self._timer_claims += 1
            return out
        return super().on_role_timer(name)

    def _on_relay(self, payload: bytes, link: str) -> list[Frame]:
        try:
            final_dst, inner = m.decode_relay(payload)
        except DecodeError as exc:
            raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
        if link == self.cfg.id_bs:
            if not self.check("relay target is a granted member", final_dst in self.grant):
                raise Rejected("UNAUTHORISED_PEER", peer=final_dst, reason="not a granted member")
            return [self.frame(final_dst, m.label(inner), inner)]
        if not self.check("relaying member is granted", link in self.grant):
            raise Rejected("UNAUTHORISED_PEER", peer=link, reason="relay from a non-granted device")
        if final_dst != self.cfg.id_bs:
            raise Rejected("WRONG_RECIPIENT", peer=link)
        return [self.frame(self.cfg.id_bs, m.label(payload), payload)]


class CMMembership(EnhancedDevice):
    role = dv.CM

    def __init__(self, *args: Any, deployed_ch: str, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.relay_ch: str | None = deployed_ch  # radio neighbour used to reach the BS
        self.designated: str | None = None  # only a BS DESIGNATION sets this
        self.designation_epoch = -1

    def handlers(self) -> dict[int, Any]:
        return {**super().handlers(), m.CLUSTER_OPEN: self._on_open, m.DESIGNATION: self._on_designation}

    def start_onboarding(self) -> list[Frame]:
        return self.start_ake(self.cfg.id_bs, m.CM_BS, self.relay_ch, fresh_budget=True)

    def screen_hs1(self, hs1: m.Hs1) -> str | None:
        return "NOT_DESIGNATED" if hs1.id_i != self.designated else None

    def may_initiate(self, peer: str, purpose: str) -> str | None:
        if purpose == m.CM_CH and peer != self.designated:
            return "NOT_DESIGNATED"
        return None

    def on_established(self, s: Session) -> list[Frame]:
        if s.purpose == m.CM_BS and self.status in (dv.PROVISIONED, dv.FAILED):
            self.set_status(dv.REGISTERED)
        elif s.purpose == m.CM_CH:
            self.set_status(dv.ACTIVE)
            self.emit("DEVICE_ACTIVE", peer=s.peer)
        return []

    def on_gave_up(self, s: Session) -> list[Frame]:
        self.set_status(dv.FAILED)
        return []

    def _on_open(self, payload: bytes, link: str) -> list[Frame]:
        try:
            _epoch, id_ch = m.decode_open(payload)
        except DecodeError as exc:
            raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
        if not self.check("CLUSTER_OPEN names its sender", id_ch == link):
            raise Rejected("DECODE_ERROR", peer=link, error="CLUSTER_OPEN sender mismatch")
        if self.designated is None:
            self.relay_ch = link  # before any designation, the open is how a member finds its relay
        # Once designated, only an authenticated DESIGNATION moves the relay: a forged open is used
        # for the one handshake it triggers and cannot redirect later ones (follow-up E3, R-13).
        if self.current_session(self.cfg.id_bs, m.CM_BS) is None or self.designated != link:
            return self.start_ake(self.cfg.id_bs, m.CM_BS, link, fresh_budget=True)
        if self.current_session(link, m.CM_CH) is None:
            return self.start_ake(link, m.CM_CH, fresh_budget=True)
        return []

    def _on_designation(self, payload: bytes, link: str) -> list[Frame]:
        with ledger.LedgerScope(self.identity, "membership"):
            s, _, pt = self.open_sealed(payload, peer=self.cfg.id_bs, purpose=m.CM_BS, notify_via=link)
            try:
                epoch, id_ch = m.decode_epoch_id(pt)
            except DecodeError as exc:
                raise Rejected("DECODE_ERROR", peer=link, error=str(exc)) from exc
        if not self.check("designation epoch not stale", epoch >= self.designation_epoch):
            raise Rejected("REPLAY_REJECTED", peer=link, reason="stale designation")
        self.learn_epoch(epoch, s)
        if self.designated is not None and self.designated != id_ch:
            self.drop_peer(self.designated)
        self.designated, self.designation_epoch = id_ch, epoch
        self.relay_ch = id_ch
        self.emit("DESIGNATED", peer=id_ch, epoch=epoch)
        if self.status in (dv.PROVISIONED, dv.REGISTERED, dv.FAILED):
            self.set_status(dv.AUTHENTICATED)
        if self.current_session(id_ch, m.CM_CH) is None:
            return self.start_ake(id_ch, m.CM_CH, fresh_budget=True)
        return []
