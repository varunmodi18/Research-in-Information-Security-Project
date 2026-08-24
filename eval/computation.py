"""RP9 §7.1, Table 2: computation cost, derived from the ledger on F-PAPER (P12.2)."""

from __future__ import annotations

from eval import cost_model
from maka import fixtures, ledger, params, trace
from maka.network import Network
from maka.protocol import (
    data_transmission,
    p1_initialization,
    p2_key_generation,
    p3_node_registration,
    p4_node_authentication,
    p5_session_key_agreement,
)

CM_FORMULA = {"T_HG": 1, "T_SM": 4, "T_E/D": 2, "T_P": 1}
CH_FORMULA = {"T_HG": 1, "T_SM": 4, "T_E/D": 4, "T_P": 1}


def _run_paper_fixture(params_name: str) -> Network:

    p = params.get(params_name)
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    p4_node_authentication.run(net, fixtures.PAPER)
    p5_session_key_agreement.run(net, fixtures.PAPER)
    data_transmission.run(net)
    return net


def _totals_for(entity: str) -> dict[str, int]:
    return ledger.current().total(entity)


def run(params_name: str = "demo") -> dict[str, dict[str, int]]:
    t = trace.active()
    t.section("7.1", "Table 2: computation cost (ledger-derived)")
    fixtures.assert_paper_table_allowed(fixtures.PAPER)

    ledger.current().reset()
    net = _run_paper_fixture(params_name)

    ch = next(iter(net.cluster_heads.values()))
    cm = next(iter(net.cluster_members[ch.identity].values()))

    cm_totals = _totals_for(cm.identity)
    ch_totals = _totals_for(ch.identity)

    rows = []
    for op in cost_model.ALL:
        rows.append([op, cm_totals.get(op, 0), ch_totals.get(op, 0), f"{cost_model.ALL[op]} ms"])
    t.table(["op", "CM count", "CH count", "cost/op"], rows, "Table 2 -- ledger-derived operation counts")

    for op, expected in CM_FORMULA.items():
        actual = cm_totals.get(op, 0)
        t.check(f"CM {op} == {expected} (RP9-stated formula: 1T_HG+4T_SM+2T_E/D+1T_P)",
                actual == expected, expected, actual)
    for op, expected in CH_FORMULA.items():
        actual = ch_totals.get(op, 0)
        t.check(f"CH {op} == {expected} (RP9-stated formula: 1T_HG+4T_SM+4T_E/D+1T_P)",
                actual == expected, expected, actual)

    # RP9's Table 2 totals cover key generation/registration/authentication/session-key
    # phases only (1T_HG+4T_SM+2or4 T_E/D+1T_P); data-transmission's T_S is a later phase
    # RP9's Table 2 does not itemise, so it is excluded from this comparison.
    cm_ms = sum(cm_totals.get(op, 0) * cost_model.ALL[op] for op in CM_FORMULA)
    ch_ms = sum(ch_totals.get(op, 0) * cost_model.ALL[op] for op in CH_FORMULA)
    t.value("CM total (ledger-derived, Table 2 ops only)", f"{cm_ms:.3f} ms")
    t.value("CH total (ledger-derived, Table 2 ops only)", f"{ch_ms:.3f} ms")

    return {"CM": cm_totals, "CH": ch_totals}
