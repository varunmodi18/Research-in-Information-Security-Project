"""V-LEAK-01 (CLI part): no SECRET-class value appears in any CLI transcript, log or stdout,
at verbosity 3, under default settings (IMPLEMENTATION_PLAN.md M1-T7, I-09)."""

from __future__ import annotations

from pathlib import Path

import pytest

from maka import cli, hashing
from maka.entities.base_station import BaseStation
from maka.network import Network
from maka.protocol import p1_initialization

from .leakscan import scan_text


class Collector:
    def __init__(self) -> None:
        self.nets: list[Network] = []
        self.extra: dict[str, object] = {}

    def secrets(self) -> dict[str, object]:
        out = dict(self.extra)
        for i, net in enumerate(self.nets):
            out[f"net{i}.Pr_BS"] = net.bs.pr_bs
            for ident, sk in net.bs.session_keys.items():
                out[f"net{i}.SK_BS-{ident}"] = sk
            for ident, key in net.sym_keys.items():
                out[f"net{i}.k_sym.{ident}"] = key
            for ch in net.cluster_heads.values():
                out[f"net{i}.Pr_{ch.identity}"] = ch.pr_i
                out[f"net{i}.r_CH.{ch.identity}"] = ch.r_ch
                for cm in net.cluster_members[ch.identity].values():
                    out[f"net{i}.Pr_{cm.identity}"] = cm.pr_i
                    out[f"net{i}.r_CM.{cm.identity}"] = cm.r_cm
        return {k: v for k, v in out.items() if v is not None}


@pytest.fixture
def collector(monkeypatch: pytest.MonkeyPatch) -> Collector:
    c = Collector()
    real_p1 = p1_initialization.run
    real_gen = BaseStation.generate_parameters
    real_kdf = hashing.kdf

    def p1_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        net = real_p1(*args, **kwargs)
        c.nets.append(net)
        return net

    def gen(self, k_scalar):  # type: ignore[no-untyped-def]
        c.extra[f"k#{len(c.extra)}"] = k_scalar
        return real_gen(self, k_scalar)

    def kdf(gt_repr, label, nbytes):  # type: ignore[no-untyped-def]
        out = real_kdf(gt_repr, label, nbytes)
        if label == b"MAKA-IBE-DEM":
            c.extra[f"dem_key#{len(c.extra)}"] = out
            c.extra[f"dem_shared#{len(c.extra)}"] = gt_repr
        return out

    monkeypatch.setattr(p1_initialization, "run", p1_run)
    monkeypatch.setattr(BaseStation, "generate_parameters", gen)
    monkeypatch.setattr(hashing, "kdf", kdf)
    return c


def _run_cli(argv: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> list[str]:
    assert cli.main([*argv, "-vvv", "--no-color", "--out", str(tmp_path)]) == 0
    out = capsys.readouterr()
    texts = [out.out, out.err]
    texts += [f.read_text(encoding="utf-8") for f in tmp_path.iterdir() if f.suffix in (".log", ".jsonl")]
    return texts


def test_v_leak_01_cli_run(tmp_path: Path, collector: Collector, capsys: pytest.CaptureFixture[str]) -> None:
    texts = _run_cli(["run", "--params", "demo", "--fixture", "paper"], tmp_path, capsys)
    secrets = collector.secrets()
    assert len(secrets) >= 10  # k, Pr_*, r_*, SKs, k_sym, IBE DEM keys
    assert scan_text(secrets, texts) == []


def test_v_leak_01_scanner_detects_disclosure(tmp_path: Path, collector: Collector,
                                              capsys: pytest.CaptureFixture[str]) -> None:
    """The same run with --disclose-secrets must produce hits, or the scan proves nothing."""
    texts = _run_cli(["run", "--params", "demo", "--fixture", "paper", "--disclose-secrets"],
                     tmp_path, capsys)
    assert scan_text(collector.secrets(), texts)


@pytest.mark.slow
def test_v_leak_01_cli_all(tmp_path: Path, collector: Collector, capsys: pytest.CaptureFixture[str]) -> None:
    texts = _run_cli(["all", "--params", "demo", "--fixture", "paper"], tmp_path, capsys)
    assert scan_text(collector.secrets(), texts) == []
