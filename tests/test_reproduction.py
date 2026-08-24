"""§9.1 hard assertions on F-PAPER; §9.2 reported not asserted (P12 DoD)."""

from __future__ import annotations

from eval import communication, comparison, computation, storage

from maka import rng, trace


def _fresh(run_id: str) -> None:
    rng.seed(30)
    trace.init(run_id=run_id, out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)


def test_table2_computation_hard_assertion() -> None:
    _fresh("test-table2")
    totals = computation.run("toy")
    assert totals["CM"]["T_HG"] == 1
    assert totals["CM"]["T_SM"] == 4
    assert totals["CM"]["T_E/D"] == 2
    assert totals["CM"]["T_P"] == 1
    assert totals["CH"]["T_HG"] == 1
    assert totals["CH"]["T_SM"] == 4
    assert totals["CH"]["T_E/D"] == 4
    assert totals["CH"]["T_P"] == 1


def test_table3_communication_hard_assertion() -> None:
    _fresh("test-table3")
    totals = communication.run("toy")
    assert totals["key generation"] == 640
    assert totals["registration"] == 1760
    assert totals["authentication"] == 2400
    assert totals["session key agreement"] == 0


def test_table5_maka_recomputation() -> None:
    _fresh("test-table5")
    comparison.run_table5()  # asserts internally via trace.check; no exception == pass


def test_storage_does_not_raise_on_underspecification() -> None:
    """P12.4: a build must not fail because RP9 is silent about retention policy."""
    _fresh("test-table4")
    storage.run("toy")  # must not raise
