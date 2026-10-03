"""Builds and drives an original-mode network on the runtime (IMPLEMENTATION_PLAN.md §4.7).

Original mode is lab-only (NFR-SEC-03): building it on a product bus is refused.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from typing import cast

from maka import codec, fixtures, hashing, ledger, params, rng, trace
from maka.original_rt.states import (
    T_AUTH,
    T_REG,
    OriginalBS,
    OriginalCH,
    OriginalCM,
    OriginalConfig,
)
from maka.runtime.bus import LAB, Bus
from maka.runtime.errors import ModeNotAllowed
from maka.runtime.keystore import Keystore, SecretClass
from maka.runtime.scheduler import Scheduler, StepResult


@dataclass
class OriginalNetwork:
    scheduler: Scheduler
    cfg: OriginalConfig
    topology: dict[str, object]
    params_name: str
    source: rng.RandomSource
    ledger: ledger.Ledger = field(default_factory=ledger.Ledger)
    mode: str = "original"

    @contextmanager
    def context(self) -> Iterator[None]:
        """Scopes this network's randomness, ledger and (null) tracer to the calling thread."""
        with ExitStack() as stack:
            stack.enter_context(rng.using(self.source))
            stack.enter_context(ledger.using(self.ledger))
            stack.enter_context(trace.using(trace.NullTracer()))
            yield

    @property
    def bs_id(self) -> str:
        return self.cfg.id_bs

    def chs(self) -> dict[str, list[str]]:
        return cast(dict[str, list[str]], self.topology["chs"])

    def device(self, ident: str):  # type: ignore[no-untyped-def]
        return self.scheduler.devices[ident]

    def _bs(self) -> OriginalBS:
        return cast(OriginalBS, self.scheduler.devices[self.bs_id])

    def _ch(self, ident: str) -> OriginalCH:
        return cast(OriginalCH, self.scheduler.devices[ident])

    def start_onboarding(self) -> list[StepResult]:
        """RP9 §5.2 key generation on every device; the rest of §5.3-5.5 is event-driven."""
        with self.context():
            out = [self.scheduler.command(self.bs_id, "keygen")]
            for ch_id, cms in self.chs().items():
                out.append(self.scheduler.command(ch_id, "keygen"))
                out.extend(self.scheduler.command(cm_id, "keygen") for cm_id in cms)
        return out

    def run(self, max_steps: int = 20_000,
            should_stop: Callable[[], bool] | None = None) -> list[StepResult]:
        with self.context():
            return self.scheduler.run_until_quiescent(max_steps, should_stop)

    def step(self, n: int = 1) -> list[StepResult]:
        with self.context():
            return self.scheduler.run_steps(n)

    def onboard(self, max_steps: int = 20_000) -> list[StepResult]:
        return self.start_onboarding() + self.run(max_steps)

    def send_reading(self, cm_id: str, value: str) -> StepResult:
        with self.context():
            return self.scheduler.command(cm_id, "send_reading", value)

    # -- read-only views for the console (public metadata only) ---------------------------

    def device_epoch(self, ident: str) -> int:
        return 0  # RP9 has no revocation, so no epochs (OB-05)

    def readings(self) -> list[dict[str, object]]:
        return list(self._bs().readings)

    def session_infos(self) -> list[dict[str, object]]:
        """RP9 §5.5's static SK_{i-BS}, shown as a session per node that derived it. It is
        'unconfirmed' unless the BS (for a CH) or the CH (for a CM) authenticated that node,
        because RP9 gives no key confirmation (P-04)."""
        out: list[dict[str, object]] = []
        bs = self._bs()
        for ch_id, cms in self.chs().items():
            ch = self._ch(ch_id)
            for ident, confirmed in [(ch_id, ch_id in bs.authenticated_chs)] + [
                    (cm, cm in ch.authenticated_members) for cm in cms]:
                if self.scheduler.devices[ident].keystore.has("ksym"):
                    out.append({"a": ident, "b": self.bs_id, "purpose": "SK-BS",
                                "state": "ESTABLISHED" if confirmed else "UNCONFIRMED", "sid_hex": "",
                                "established_step": None, "epoch": 0, "sent": 0, "recv": 0})
        return out


def build(params_name: str, topology: str | dict[str, object], *, kind: str = LAB,
          seed: int | None = None, secure_pseudo_ids: bool = True,
          forward_ciphertexts: bool = False) -> OriginalNetwork:
    if kind != LAB:
        raise ModeNotAllowed("original (RP9) mode runs only on lab networks (NFR-SEC-03)")
    pset = params.get(params_name)
    topo = fixtures.topology(topology) if isinstance(topology, str) else topology
    source: rng.RandomSource = rng.Rng(seed=seed) if seed is not None else rng.SystemSource()
    chs = cast(dict[str, list[str]], topo["chs"])
    n_devices = 1 + sum(1 + len(cms) for cms in chs.values())
    cfg = OriginalConfig(curve=pset.curve, g=pset.g, id_bs=str(topo["bs"]),
                         secure_pseudo_ids=secure_pseudo_ids, forward_ciphertexts=forward_ciphertexts,
                         t_reg=max(T_REG, 4 * n_devices), t_auth=max(T_AUTH, 8 * n_devices))
    net = OriginalNetwork(scheduler=Scheduler(Bus(kind=kind)), cfg=cfg, topology=topo,
                          params_name=params_name, source=source)
    curve, g = pset.curve, pset.g

    with net.context():
        # RP9 §5.1: the BS generates k and its key pair; every node is preloaded with k.
        bs_ks = Keystore(cfg.id_bs)
        with ledger.LedgerScope(cfg.id_bs, "init"):
            k = source.randint(1, curve.r_group)
            pu_bs = hashing.hash_to_point(curve, cfg.id_bs.encode())
            pr_bs, k_pub = k * pu_bs, k * g
        public = {"pu_bs": codec.enc_point(pu_bs), "k_pub": codec.enc_point(k_pub)}

        def preload(ks: Keystore) -> Keystore:
            ks.put("k", codec.enc_scalar(curve, k), SecretClass.SECRET)
            for name, value in public.items():
                ks.put(name, value, SecretClass.PUBLIC)
            return ks

        preload(bs_ks)
        bs_ks.put("pr", codec.enc_point(pr_bs), SecretClass.SECRET)
        bs_ks.put("pu", public["pu_bs"], SecretClass.PUBLIC)
        net.scheduler.add_device(OriginalBS(cfg.id_bs, bs_ks, source.spawn(cfg.id_bs), cfg))
        for ch_id, cms in net.chs().items():
            net.scheduler.add_device(OriginalCH(ch_id, preload(Keystore(ch_id)), source.spawn(ch_id),
                                                cfg, expected_members=list(cms)))
            for cm_id in cms:
                net.scheduler.add_device(OriginalCM(cm_id, preload(Keystore(cm_id)), source.spawn(cm_id),
                                                    cfg, deployed_ch=ch_id))
    return net
