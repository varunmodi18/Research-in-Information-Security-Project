"""Lab scenarios L1-L8 (IMPLEMENTATION_PLAN.md §3.6, M6-T1, M6-T3).

Each scenario runs on a fresh lab network in one mode ("original" = RP9 as published,
"enhanced" = MAKA-E v1): setup() builds and prepares it, attack() drives the adversary,
judge() decides ATTACK SUCCEEDED / ATTACK BLOCKED from what actually happened -- linked frames
and events -- never from the expected outcome. The expectation is reported next to the result.
Verdicts name secrets, never contain them (§4.4).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, cast

from cryptography.exceptions import InvalidTag

from maka import aead, codec, hashing, ibe, pairing
from maka.codec import DecodeError
from maka.enhanced import messages as em
from maka.enhanced import network as en
from maka.field import fp2_to_bytes
from maka.lab import attacker
from maka.original_rt import messages as om
from maka.original_rt import network as onet
from maka.protocol.data_transmission import data_ad
from maka.protocol.p5_session_key_agreement import K_SYM_BYTES, k_sym_label
from maka.rng import Rng
from maka.runtime import adversary
from maka.runtime.bus import Frame
from maka.runtime.events import SecurityEvent

SUCCEEDED = "ATTACK SUCCEEDED"
BLOCKED = "ATTACK BLOCKED"
ORIGINAL, ENHANCED = "original", "enhanced"
MODES = (ORIGINAL, ENHANCED)
DEFAULT_SEED = 20260927

Net = onet.OriginalNetwork | en.EnhancedNetwork


@dataclass
class Verdict:
    result: str
    explanation: str
    evidence_frame_ids: list[int] = field(default_factory=list)
    event_indices: list[int] = field(default_factory=list)
    secrets_obtained: list[str] = field(default_factory=list)  # names only (M6-T3)
    measurements: dict[str, Any] = field(default_factory=dict)


@dataclass
class Run:
    """One scenario execution: the network, the adversary's notes, and the verdict."""

    scenario: str
    mode: str
    net: Net
    rng: Rng
    notes: dict[str, Any] = field(default_factory=dict)
    verdict: Verdict | None = None

    def events(self, etype: str | None = None, since: int = 0) -> list[tuple[int, SecurityEvent]]:
        return [(i, e) for i, e in enumerate(self.net.scheduler.events) if i >= since
                and (etype is None or e.type == etype)]

    def inject(self, src: str, dst: str, label: str, payload: bytes) -> int:
        with self.net.context():
            frame = self.net.scheduler.bus.inject(Frame(src, dst, label, payload), self.net.scheduler.step_no)
        return frame.frame_id

    def device(self, ident: str) -> Any:
        """The device object, for insider manipulation (AT3) by Lab code only."""
        return self.net.scheduler.devices[ident]

    def by_frame(self, frame_id: int) -> list[tuple[int, SecurityEvent]]:
        return [(i, e) for i, e in self.events() if e.frame_id == frame_id]


def _expect(original: str, enhanced: str) -> MappingProxyType[str, str]:
    """The outcome §3.6 predicts per mode -- reported next to the actual result, never used to set it."""
    return MappingProxyType({ORIGINAL: original, ENHANCED: enhanced})


class Scenario:
    id = ""
    title = ""
    gap = ""
    expected = _expect(BLOCKED, BLOCKED)
    summary = ""

    def describe(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "gap": self.gap, "summary": self.summary,
                "expected": dict(self.expected)}

    def setup(self, mode: str, params: str, topology: str, seed: int) -> Run:
        net: Net = (onet.build(params, topology, seed=seed) if mode == ORIGINAL
                    else en.build(params, topology, seed=seed))
        return Run(self.id, mode, net, Rng(seed=seed).spawn(f"adversary-{self.id}-{mode}"))

    def attack(self, run: Run) -> None:
        raise NotImplementedError

    def judge(self, run: Run) -> Verdict:
        raise NotImplementedError

    def execute(self, mode: str, params: str = "toy", topology: str = "small", seed: int = DEFAULT_SEED) -> Run:
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}")
        run = self.setup(mode, params, topology, seed)
        with run.net.context():  # adversary computations also use this network's null tracer
            self.attack(run)
            run.verdict = self.judge(run)
        return run


def _accepting(run: Run, frame_id: int) -> list[tuple[int, SecurityEvent]]:
    ok = {"ORIG_AUTH_OK", "HANDSHAKE_OK", "KEY_CONFIRMED", "DATA_ACCEPTED", "ORIG_REGISTERED"}
    return [(i, e) for i, e in run.by_frame(frame_id) if e.type in ok]


def _verdict_by_frame(run: Run, frame_id: int, what: str) -> Verdict:
    accepted = _accepting(run, frame_id)
    linked = run.by_frame(frame_id)
    if accepted:
        return Verdict(SUCCEEDED, f"The receiver accepted the {what} ({accepted[0][1].type} at "
                       f"{accepted[0][1].device}).", [frame_id], [i for i, _ in linked])
    delivered = [r for r in run.net.scheduler.log if r.frame is not None and r.frame.frame_id == frame_id]
    reason = next((r.reason for r in delivered if r.reason), None) or (linked[0][1].type if linked else "no acceptance")
    return Verdict(BLOCKED, f"The receiver rejected the {what} ({reason}).", [frame_id], [i for i, _ in linked])


# -- L1 replay ------------------------------------------------------------------------------------

class L1Replay(Scenario):
    id, title, gap = "L1", "Replay a captured authentication message", "P-08, S1"
    expected = _expect(BLOCKED, BLOCKED)
    summary = "Record CH-01's first authentication message to CM-0101 and replay it after onboarding."

    def attack(self, run: Run) -> None:
        label = om.EM1 if run.mode == ORIGINAL else "HS1"
        if run.mode == ORIGINAL:
            rec = adversary.Record(lambda f: f.label == om.EM1 and f.dst == "CM-0101")
        else:
            rec = adversary.Record(lambda f: f.label == "HS1" and f.src == "CM-0101" and f.dst == "CH-01")
        run.net.scheduler.bus.add_interceptor(rec)
        run.net.onboard()
        captured = rec.frames[0]
        run.notes["frame_id"] = run.inject(captured.src, captured.dst, label, captured.payload)
        run.net.run()

    def judge(self, run: Run) -> Verdict:
        return _verdict_by_frame(run, run.notes["frame_id"], "replayed authentication message")


# -- L2 tamper ---------------------------------------------------------------------------------

class L2Tamper(Scenario):
    id, title, gap = "L2", "Tamper with one byte of an authentication message in transit", "I-01"
    expected = _expect(BLOCKED, BLOCKED)
    summary = "Flip the last byte of the CH's authentication message to CM-0101 on the channel."

    def attack(self, run: Run) -> None:
        if run.mode == ORIGINAL:
            pred = lambda f: f.label == om.EM1 and f.dst == "CM-0101"
        else:
            pred = lambda f: f.label == "HS2" and f.dst == "CM-0101" and em.decode_hs2(f.payload).id_r == "CH-01"
        mod = adversary.Modify(pred, adversary.flip_byte(-1), limit=1)
        run.net.scheduler.bus.add_interceptor(mod)
        run.net.onboard()
        run.notes["frame_id"] = mod.hit_frame_ids[0]
        run.notes["recovered"] = run.net.device("CM-0101").status == "active"

    def judge(self, run: Run) -> Verdict:
        v = _verdict_by_frame(run, run.notes["frame_id"], "tampered message")
        v.measurements["victim_active_afterwards"] = run.notes["recovered"]
        if v.result == BLOCKED:
            v.explanation += (" A fresh handshake then succeeded." if run.notes["recovered"] else
                              " RP9 has no retry, so CM-0101 timed out and stayed unauthenticated.")
        return v


# -- L3 insider impersonation ----------------------------------------------------------------------

class L3InsiderImpersonation(Scenario):
    id, title, gap = "L3", "Insider CM impersonates its CH to another CM", "P-01"
    expected = _expect(SUCCEEDED, BLOCKED)
    summary = "CM-0101 uses only its own keys and public values to pose as CH-01 towards CM-0102."

    def attack(self, run: Run) -> None:
        net = run.net
        net.onboard()
        insider = net.device("CM-0101")
        if run.mode == ORIGINAL:
            k_pub = codec.load_point(insider.curve, insider.keystore.get("k_pub"))
            forged = attacker.forge_rp9_em1(insider.curve, insider.g, run.rng, k_pub, "BS-01", "CH-01", "CM-0102")
            run.notes["frame_id"] = run.inject("CH-01", "CM-0102", om.EM1, forged)
            net.run()
            return
        enet = cast(en.EnhancedNetwork, net)
        stolen = insider.keystore.snapshot()
        rec = adversary.Record(lambda f: f.label == "HS1" and f.src == "CM-0102" and f.dst == "CH-01")
        enet.scheduler.bus.add_interceptor(rec)
        enet.scheduler.bus.add_interceptor(adversary.Drop(lambda f: f.label == "HS1" and f.src == "CM-0102", limit=1))
        enet.rekey("CM-0102", "CH-01")
        enet.step(1)
        forged = attacker.forge_hs2(insider.curve, insider.g, run.rng, rec.frames[-1].payload, stolen["psk:CH-01"])
        run.notes["frame_id"] = run.inject("CH-01", "CM-0102", "HS2", forged)
        enet.run()

    def judge(self, run: Run) -> Verdict:
        return _verdict_by_frame(run, run.notes["frame_id"], "forged CH authentication")


# -- L4 fake base station ------------------------------------------------------------------------------

class L4FakeBaseStation(Scenario):
    id, title, gap = "L4", "Fake base station answers a CH", "P-03"
    expected = _expect(SUCCEEDED, BLOCKED)
    summary = "Suppress the BS's reply to CH-01 and answer in its place without the BS's private key."

    def attack(self, run: Run) -> None:
        net = run.net
        ch = net.device("CH-01")
        if run.mode == ORIGINAL:
            net.scheduler.bus.add_interceptor(adversary.Drop(lambda f: f.label == om.PSEUDO_BS_CH, limit=1))
            net.start_onboarding()
            net.run()
            fake = [run.rng.randint(1, ch.curve.r_group) * ch.g for _ in range(4)]
            k_pub = codec.load_point(ch.curve, ch.keystore.get("k_pub"))
            with net.context():
                sealed = codec.encode_ibe(ibe.encrypt(ch.curve, ch.g, codec.encode_pseudo_bs_ch(fake[0], fake[1:]),
                                                      hashing.hash_to_point(ch.curve, b"CH-01"), k_pub))
            run.notes["fake_p_ch"] = fake[0]
            run.notes["frame_id"] = run.inject("BS-01", "CH-01", om.PSEUDO_BS_CH, sealed)
            net.run()
            return
        rec = adversary.Record(lambda f: f.label == "HS1" and f.dst == "BS-01")
        net.scheduler.bus.add_interceptor(rec)
        net.scheduler.bus.add_interceptor(adversary.Drop(lambda f: f.label == "HS1" and f.dst == "BS-01", limit=1))
        net.start_onboarding()
        forged = attacker.forge_hs2(ch.curve, ch.g, run.rng, rec.frames[0].payload, run.rng.bytes(32))
        run.notes["frame_id"] = run.inject("BS-01", "CH-01", "HS2", forged)
        net.run()

    def judge(self, run: Run) -> Verdict:
        if run.mode == ORIGINAL:
            ch = run.net.device("CH-01")
            fid = run.notes["frame_id"]
            linked = [i for i, _ in run.by_frame(fid)]
            if getattr(ch, "p_ch", None) == run.notes["fake_p_ch"]:
                return Verdict(SUCCEEDED, "CH-01 accepted pseudo-identities chosen by the fake BS: nothing in "
                               "RP9 authenticates the BS to the CH, and K_pub and H(ID_CH) are public.", [fid], linked)
            return Verdict(BLOCKED, "CH-01 did not adopt the fake values.", [fid], linked)
        return _verdict_by_frame(run, run.notes["frame_id"], "fake base station's HS2")


# -- L5 device capture -----------------------------------------------------------------------------------

class L5DeviceCapture(Scenario):
    id, title, gap = "L5", "Device capture: the adversary obtains one CM's keystore", "P-05, P-04"
    expected = _expect(SUCCEEDED, BLOCKED)
    summary = ("Capture CM-0101. Success means the capture exposes another device's keys or the "
               "captured device's past traffic; exposure of the captured device itself is expected.")

    def attack(self, run: Run) -> None:
        if run.mode == ORIGINAL:
            self._attack_original(run)
        else:
            self._attack_enhanced(run)

    def _attack_original(self, run: Run) -> None:
        net = cast(onet.OriginalNetwork, run.net)
        early = adversary.capture(net.scheduler, "CM-0101")  # before keygen: RP9 preloads k (§5.1)
        net.onboard()
        rec_frames: list[Frame] = []
        for cm in ("CM-0101", "CM-0102"):
            rec_frames += [r.emitted[0] for r in [net.send_reading(cm, f"secret reading of {cm}")] if r.emitted]
        net.run()
        late = adversary.capture(net.scheduler, "CM-0101")
        cm = net.device("CM-0101")
        curve = cm.curve
        exposed: list[str] = []
        k = codec.dec_scalar(curve, early["k"]) if "k" in early else None
        pu_bs = codec.load_point(curve, late["pu_bs"])
        for frame in rec_frames:
            seq, blob = codec.decode_data(frame.payload)
            if frame.src == "CM-0101":
                pr = codec.load_point(curve, late["pr"])  # captured after onboarding
            elif k is not None:
                pr = k * hashing.hash_to_point(curve, frame.src.encode())  # any device, from k
            else:
                continue
            key = hashing.kdf(fp2_to_bytes(pairing.modified_pairing(curve, pr, pu_bs)), k_sym_label("BS-01", frame.src),
                              K_SYM_BYTES)
            try:
                aead.decrypt(key, blob, ad=data_ad(frame.src, "BS-01", seq))
                exposed.append(frame.src)
            except InvalidTag:
                pass
        run.notes.update(names=sorted(set(early) | set(late)), exposed=exposed,
                         frames=[f.frame_id for f in rec_frames])

    def _attack_enhanced(self, run: Run) -> None:
        net = cast(en.EnhancedNetwork, run.net)
        rec = adversary.Record(lambda f: f.label in ("HS1", "HS2", "DATA_CM", "RELAY:HS1", "RELAY:HS2"))
        net.scheduler.bus.add_interceptor(rec)
        net.onboard()
        for member in ("CM-0101", "CM-0102"):
            net.send_reading(member, f"secret reading of {member}")
        net.run()
        net.rekey("CM-0101")  # the recorded sessions end; their keys are destroyed
        net.run()
        stolen = adversary.capture(net.scheduler, "CM-0101")
        cm = net.device("CM-0101")
        exposed: list[str] = []
        for frame in [f for f in rec.frames if f.label == "DATA_CM"]:
            _, inner, _ = em.decode_data_cm(frame.payload)
            sec = em.decode_secure(inner)
            ad = em.secure_ad(sec.mtype, sec.sid, frame.src, "BS-01", sec.seq)
            for value in stolen.values():
                if len(value) != 32:
                    continue
                try:
                    aead.decrypt(value, sec.ct, ad=ad)
                    exposed.append(frame.src)
                    break
                except (InvalidTag, ValueError):
                    pass
        hs: dict[bytes, dict[str, bytes]] = {}
        for f in rec.frames:
            inner = em.decode_relay(f.payload)[1] if f.label.startswith("RELAY:") else f.payload
            try:
                if em.mtype(inner) == em.HS1:
                    h1 = em.decode_hs1(inner)
                    if h1.id_i == "CM-0101" and h1.purpose == em.CM_BS:
                        hs.setdefault(h1.sid, {})["hs1"] = inner
                elif em.mtype(inner) == em.HS2:
                    h2 = em.decode_hs2(inner)
                    if h2.id_i == "CM-0101" and h2.id_r == "BS-01":
                        hs.setdefault(h2.sid, {})["hs2"] = inner
            except DecodeError:
                continue
        first = next(v for v in hs.values() if "hs1" in v and "hs2" in v)
        pr = codec.load_point(cm.curve, stolen["pr"])
        x_pt = codec.dec_point(cm.curve, em.decode_hs1(first["hs1"]).x_raw)
        y_pt = codec.dec_point(cm.curve, em.decode_hs2(first["hs2"]).y_raw)
        past_session = attacker.try_derive_session(cm.curve, first["hs1"], first["hs2"], stolen["psk:BS-01"],
                                                   [x_pt, y_pt, x_pt + y_pt, pr, pr + y_pt])
        other_device_keys = any(n == "k" or (n.startswith("psk:") and n != "psk:BS-01" and n != "psk:CH-01")
                                for n in stolen)
        run.notes.update(names=sorted(stolen), exposed=exposed, past_session=past_session,
                         other_device_keys=other_device_keys,
                         frames=[f.frame_id for f in rec.frames if f.label == "DATA_CM"])

    def judge(self, run: Run) -> Verdict:
        names = run.notes["names"]
        exposed = sorted(set(run.notes["exposed"]))
        others = [d for d in exposed if d != "CM-0101"]
        frames = run.notes["frames"]
        if run.mode == ORIGINAL:
            ok = bool(others) or "CM-0101" in exposed
            text = ("Captured before key generation, CM-0101 held the master key k (RP9 §5.1), so every "
                    f"device's key follows: readings of {', '.join(exposed)} were decrypted. Captured "
                    "afterwards, its static key decrypts all of its own past and future traffic (P-04).")
            return Verdict(SUCCEEDED if ok else BLOCKED, text, frames, [], names,
                           {"decrypted_devices": exposed, "master_key_captured": "k" in names})
        ok = bool(others) or run.notes["past_session"] or run.notes["other_device_keys"]
        text = ("Only CM-0101's own keys were obtained (no master key; C1). Recorded traffic from its ended "
                "sessions stayed confidential: the ephemeral secrets were destroyed (forward secrecy), and "
                "no other device's keys follow. The attacker can still impersonate CM-0101 itself, and "
                "impersonate peers *to* CM-0101 (KCI, an accepted residual).")
        return Verdict(SUCCEEDED if ok else BLOCKED, text, frames, [], names,
                       {"decrypted_devices": exposed, "past_session_keys_derived": run.notes["past_session"],
                        "master_key_captured": "k" in names})


# -- L6 fake member -------------------------------------------------------------------------------------

class L6FakeMember(Scenario):
    id, title, gap = "L6", "Malicious CH registers a fake member", "P-10"
    expected = _expect(SUCCEEDED, BLOCKED)
    summary = "CH-01 (an insider) lists CM-FAKE, a device the BS never provisioned, as a cluster member."

    def attack(self, run: Run) -> None:
        ch = run.device("CH-01")
        if run.mode == ORIGINAL:
            ch.members["CM-FAKE"] = hashing.hash_to_point(ch.curve, b"CM-FAKE")
            ch.expected_members.append("CM-FAKE")
        else:
            ch.member_config.append("CM-FAKE")
        run.net.onboard()

    def judge(self, run: Run) -> Verdict:
        if run.mode == ORIGINAL:
            bs = run.device("BS-01")
            reg = run.events("ORIG_REGISTERED")
            frames = [e.frame_id for _, e in reg if e.frame_id]
            if "CM-FAKE" in bs.clusters.get("CH-01", {}):
                return Verdict(SUCCEEDED, "The BS registered CM-FAKE and computed a pseudo-identity for it: RP9's "
                               "BS accepts whatever member list the CH sends.", frames, [i for i, _ in reg])
            return Verdict(BLOCKED, "The BS did not register CM-FAKE.", frames, [i for i, _ in reg])
        rejected = [(i, e) for i, e in run.events("CLAIM_REJECTED") if e.peer == "CM-FAKE"]
        granted = "CM-FAKE" in run.device("CH-01").grant
        result = SUCCEEDED if granted else BLOCKED
        return Verdict(result, "The BS checked the claim against its registry and rejected CM-FAKE "
                       "(CLAIM_REJECTED)." if not granted else "CM-FAKE was granted.",
                       [e.frame_id for _, e in rejected if e.frame_id], [i for i, _ in rejected])


# -- L7 flood -------------------------------------------------------------------------------------------

class L7Flood(Scenario):
    id, title, gap = "L7", "Flood a CH with handshake/auth messages from unknown IDs", "P-07"
    expected = _expect(SUCCEEDED, BLOCKED)
    summary = "Send 50 authentication messages from unprovisioned identities to CH-01 and count its work."
    N = 50

    def attack(self, run: Run) -> None:
        net = run.net
        net.onboard()
        ch = net.device("CH-01")
        before = dict(net.ledger.total("CH-01"))
        start = len(net.scheduler.events)
        ids = []
        for i in range(self.N):
            if run.mode == ORIGINAL:
                pu = hashing.hash_to_point(ch.curve, b"CH-01")
                k_pub = codec.load_point(ch.curve, ch.keystore.get("k_pub"))
                junk = codec.encode_auth(ch.g, ch.g, run.rng.bytes(20))
                with net.context():
                    payload = codec.encode_ibe(ibe.encrypt(ch.curve, ch.g, junk, pu, k_pub))
                ids.append(run.inject(f"EVIL-{i}", "CH-01", om.EM3, payload))
            else:
                hs1 = attacker.forge_hs1(ch.curve, ch.g, run.rng, f"EVIL-{i}", "CH-01", em.CM_CH).payload
                ids.append(run.inject(f"EVIL-{i}", "CH-01", "HS1", hs1))
        net.run()
        after = net.ledger.total("CH-01")
        run.notes.update(frames=ids, start=start,
                         cost={op: after.get(op, 0) - before.get(op, 0) for op in ("T_E/D", "T_P", "T_SM", "T_SM_val")})

    def judge(self, run: Run) -> Verdict:
        cost = run.notes["cost"]
        expensive = cost["T_E/D"] + cost["T_P"] + cost["T_SM"]
        linked = [i for i, e in run.events(since=run.notes["start"]) if e.device == "CH-01"]
        if expensive >= self.N:
            return Verdict(SUCCEEDED, f"CH-01 spent {cost['T_E/D']} IBE decryptions (each a pairing) on {self.N} "
                           "messages before rejecting them: decryption precedes any check in RP9.",
                           run.notes["frames"][:5], linked[:20], measurements={"ch_cost": cost})
        return Verdict(BLOCKED, f"CH-01 rejected all {self.N} at the ID check (UNAUTHORISED_PEER) with "
                       f"{expensive} public-key operations: checks 1-5 precede any pairing.",
                       run.notes["frames"][:5], linked[:20], measurements={"ch_cost": cost})


# -- L8 rejoin after revocation --------------------------------------------------------------------------

class L8RevokedRejoin(Scenario):
    id, title, gap = "L8", "Revoked device attempts to rejoin", "P-06"
    expected = _expect(SUCCEEDED, BLOCKED)
    summary = "Revoke CM-0102, then let it try to authenticate and send data again."

    def attack(self, run: Run) -> None:
        net = run.net
        net.onboard()
        run.notes["start"] = len(net.scheduler.events)
        if run.mode == ORIGINAL:
            run.notes["revoked"] = False  # RP9 has no revocation operation (OB-05)
            result = net.send_reading("CM-0102", "after revocation")
        else:
            enet = cast(en.EnhancedNetwork, net)
            enet.revoke("CM-0102")
            enet.run()
            run.notes["revoked"] = True
            enet.rekey("CM-0102")  # attempts CM-BS and CM-CH handshakes
            enet.run()
            result = enet.send_reading("CM-0102", "after revocation")
        run.notes["frame"] = result.emitted[0].frame_id if result.emitted else None
        net.run()

    def judge(self, run: Run) -> Verdict:
        start = run.notes["start"]
        evs = run.events(since=start)
        accepted = [(i, e) for i, e in evs if e.peer == "CM-0102" and e.type in
                    ("AGGREGATION_UNDEFINED", "DATA_ACCEPTED", "HANDSHAKE_OK")]
        refused = [(i, e) for i, e in evs if e.type in ("UNAUTHORISED_PEER", "UNAUTHENTICATED_PEER")
                   and (e.peer == "CM-0102" or e.device == "CM-0102")]
        frames = [run.notes["frame"]] if run.notes["frame"] else []
        if run.mode == ORIGINAL:
            return Verdict(SUCCEEDED if accepted else BLOCKED, "RP9 has no revocation (OB-05): the operator "
                           "cannot exclude CM-0102, and its CH still accepts its data.",
                           frames, [i for i, _ in accepted])
        result = SUCCEEDED if accepted else BLOCKED
        return Verdict(result, "Every attempt was refused: its handshakes at the ID check "
                       "(UNAUTHORISED_PEER) and its data at the CH (UNAUTHENTICATED_PEER)." if not accepted
                       else "The revoked device was accepted again.", frames, [i for i, _ in (accepted or refused)])


ALL: list[Scenario] = [L1Replay(), L2Tamper(), L3InsiderImpersonation(), L4FakeBaseStation(), L5DeviceCapture(),
                       L6FakeMember(), L7Flood(), L8RevokedRejoin()]
BY_ID = {s.id: s for s in ALL}
