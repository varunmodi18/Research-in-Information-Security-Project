"""M1-T9: every evaluation check can fail (V-EVAL-01, -02, -05). V-EVAL-03 is in
tests/test_formal.py and V-EVAL-04 in tests/test_security.py."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from eval import communication, comparison, cost_model, storage

from maka import channel, fixtures, params, rng, trace
from maka.protocol import p1_initialization, p2_key_generation, p5_session_key_agreement


@pytest.fixture(autouse=True)
def _fresh(tmp_path: Path) -> None:
    rng.seed(31)
    trace.init(run_id="test-eval", out_dir=tmp_path, color=False, verbosity=1)


def test_v_eval_01_table4_is_derived_from_state() -> None:
    rows = storage.derive_rows("toy")
    assert len(rows) == 4 and rows[0] < rows[1] <= rows[2] <= rows[3]
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    cm = net.cluster_members["CH-01"]["CM-0101"]
    before = storage.derive(cm)
    assert before == rows[0]
    cm.pu_bs = None  # mutate the stored state: the derived value must move
    assert storage.derive(cm) == before - 320


def test_v_eval_02_table3_row4_counts_frames(monkeypatch: pytest.MonkeyPatch) -> None:
    assert communication.run("toy")["session key agreement"] == 0

    original = p5_session_key_agreement._agree

    def chatty_agree(net, ident, pr_i):  # type: ignore[no-untyped-def]
        net.channel.send("DUMMY", ident, net.bs.identity, b"x", {"x": channel.Frame})  # type: ignore[dict-item]
        return original(net, ident, pr_i)

    monkeypatch.setattr("maka.wire._paper_bits", lambda item: 160)
    monkeypatch.setattr(p5_session_key_agreement, "_agree", chatty_agree)
    rng.seed(31)
    assert communication.run("toy")["session key agreement"] > 0


def test_v_eval_05_table5_transcription_is_internally_consistent() -> None:
    """Each published time must follow from its printed formula and RP9's constants, except the
    flagged rows, which must fail in exactly the documented way. A transcription error in
    either the formula or the value breaks this. The PDF check (§8) was done on 2026-10-06 by the
    plan's author, an AI reviewer, against the PDF page renders; the owner's sign-off is a separate
    field (comparison.TRANSCRIPTION_CHECK)."""
    assert len(comparison.TABLE5) == 11
    for name, formula, published, flag in comparison.TABLE5:
        recomputed = comparison.recompute(formula)
        if "ER-02" in flag:
            assert abs(recomputed - published) > 1.0, name
            assert abs(comparison.recompute(formula, {"T_SM": "T_PA"}) - published) < 5e-4, name
        elif "third-decimal" in flag:
            assert 5e-4 < abs(recomputed - published) < 5e-3, name
        else:
            assert abs(recomputed - published) < 5e-4, name
    assert cost_model.ALL["T_SM"] == 2.226


def test_v_eval_05_human_check_covers_exactly_the_tables_as_committed() -> None:
    check = comparison.TRANSCRIPTION_CHECK
    assert (check["date"], check["result"]) == ("2026-10-06", "all match")
    assert "AI reviewer" in str(check["by"]) and str(check["source"]) == "renders of the RP9 PDF pages"
    signoff = check["owner_signoff"]  # empty until the owner sets a date
    assert signoff is None or re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(signoff))
    assert check["table5_rows"] == len(comparison.TABLE5) == 11
    assert check["table6_cells"] == sum(len(c) for c in comparison.TABLE6.values()) == 11 * 9


def test_v_eval_05_table6_shape_and_prose_consistency() -> None:
    assert list(comparison.TABLE6) == comparison.SCHEMES6
    assert all(len(cells) == 9 and set(cells) <= {"Y", "N"} for cells in comparison.TABLE6.values())
    assert comparison.TABLE6["MAKA (this work)"] == ["Y"] * 9
    # RP9 §8 prose: [11], [13], [20], [22], [27], [28] suffer clock synchronisation problems.
    f9 = comparison.F_LABELS.index("F9 no clock synchronisation")
    clock = {s for s, cells in comparison.TABLE6.items() if cells[f9] == "N"}
    assert clock == {"[11]", "[13]", "[20]", "[22]", "[27]", "[28]"}
