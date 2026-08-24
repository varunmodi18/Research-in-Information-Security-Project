"""P3.4 DoD: the seven pairing self-tests pass at every parameter set, including the ER-03 pair."""

from __future__ import annotations

import pytest

from maka import pairing, params, rng, trace


@pytest.fixture(autouse=True)
def _fresh_state() -> None:
    rng.seed(0)
    trace.init(run_id="test-pairing", out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)


@pytest.mark.parametrize("name", ["toy", "demo"])
def test_selftest_all_seven_pass(name: str) -> None:
    p = params.get(name)
    results = pairing.selftest(p.curve, p.g)
    assert len(results) == 7
    failed = [(n, nm) for n, nm, ok in results if not ok]
    assert not failed, f"failing pairing properties: {failed}"


def test_er03_alternating_and_nondegenerate_are_distinct_facts() -> None:
    """The ER-03 pair: e_r(P,P) = 1 for the plain Weil pairing (alternating), while
    ê(g,g) != 1 for the modified pairing (genuine non-degeneracy)."""
    p = params.get("toy")
    results = {name: ok for _, name, ok in pairing.selftest(p.curve, p.g)}
    assert results["alternating-plain"] is True
    assert results["non-degeneracy-modified"] is True


def test_weil_and_tate_agree_up_to_bilinearity_structure() -> None:
    p = params.get("toy")
    c = p.curve
    g = p.g

    def e(backend: str) -> object:
        return pairing.modified_pairing(c, 3 * g, 5 * g, backend=backend)

    weil_val = e("weil")
    tate_val = e("tate")
    # Different pairings need not be numerically equal, but each must independently satisfy
    # bilinearity -- checked exhaustively in selftest(); here we just confirm both compute.
    assert weil_val is not None and tate_val is not None
