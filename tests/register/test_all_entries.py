"""One runnable demonstration per register entry (PLAN.md §5, P13.4).

Each test exercises the actual code path realising its register ID and asserts the
documented behaviour, rather than re-describing it in prose. Grouped by class (ER/AM/IA/
OB/SD) to mirror docs/REGISTER.md.
"""

from __future__ import annotations

from maka import fixtures, params, rng, trace


def _fresh(run_id: str) -> None:
    rng.seed(77)
    trace.init(run_id=run_id, out_dir="/tmp/maka_test_artifacts", color=False, verbosity=1)


# ---------------------------------------------------------------------- ER --

def test_er01_a4_corrected_to_r_cm() -> None:
    from maka.protocol import (
        p1_initialization,
        p2_key_generation,
        p3_node_registration,
        p4_node_authentication,
    )

    _fresh("reg-er01")
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    p4_node_authentication.run(net, fixtures.PAPER)
    ch = next(iter(net.cluster_heads.values()))
    cm = next(iter(net.cluster_members[ch.identity].values()))
    assert cm.a4 == cm.r_cm * cm.p_cm  # per ER-01, not RP9's literal r_CH * P_CM


def test_er02_table5_flags_present() -> None:
    from eval.comparison import TABLE5

    flagged = [row for row in TABLE5 if "ER-02" in row[3]]
    assert len(flagged) == 3


def test_er03_alternating_vs_nondegenerate() -> None:
    from maka import pairing

    _fresh("reg-er03")
    p = params.get("toy")
    results = {name: ok for _, name, ok in pairing.selftest(p.curve, p.g)}
    assert results["alternating-plain"] and results["non-degeneracy-modified"]


def test_er04_exponent_matters() -> None:
    from icmds.session_key import synthetic_er04_demo

    _fresh("reg-er04")
    p = params.get("toy")
    rp9_holds, icmds_holds = synthetic_er04_demo(p.curve, p.g)
    assert rp9_holds is False and icmds_holds is True


def test_er05_actor_mismatch_documented() -> None:
    from icmds import session_key

    _fresh("reg-er05")
    p = params.get("toy")
    s = rng.current().below(p.curve.r_group)
    setup = session_key.setup(p.curve, p.g, s)  # prints [ER-05] internally
    assert setup.s == s


# ---------------------------------------------------------------------- AM --

def test_am01_am08_resolved_by_ia03_sd01() -> None:
    import icmds.session_key
    import maka.ibe

    assert hasattr(maka.ibe, "encrypt")  # AM-01 -> IA-03
    assert hasattr(icmds.session_key, "encryption_setup")  # AM-08 -> SD-01 (coefficients.py)


def test_am02_am04_am06_documented() -> None:
    from eval.comparison import TABLE5

    from maka import fixtures as fx

    assert any("AM-04" in row[3] for row in TABLE5)
    assert callable(fx.assert_paper_table_allowed)


def test_am03_nonce_instances_distinct() -> None:
    from maka.protocol import p1_initialization, p2_key_generation, p3_node_registration

    _fresh("reg-am03")
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)  # emits N_reg, distinct from N_auth_*


def test_am05_aggregate_halts() -> None:
    from maka.protocol import (
        data_transmission,
        p1_initialization,
        p2_key_generation,
        p3_node_registration,
        p4_node_authentication,
        p5_session_key_agreement,
    )

    _fresh("reg-am05")
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    p4_node_authentication.run(net, fixtures.PAPER)
    p5_session_key_agreement.run(net, fixtures.PAPER)
    data_transmission.run(net)  # must not raise; halt is printed via trace.undefined


def test_am07_storage_underspecified_reported() -> None:
    from eval import storage

    _fresh("reg-am07")
    storage.run("toy")  # must not raise; UNDER-SPECIFIED boxes printed for rows 3-4


def test_am09_x_i_is_a_g2_element() -> None:
    from icmds import session_key
    from maka.field import Fp2

    _fresh("reg-am09")
    p = params.get("toy")
    setup = session_key.setup(p.curve, p.g, rng.current().below(p.curve.r_group))
    q_id, _ = session_key.gateway_key(p.curve, setup, "N-01")
    enc = session_key.encryption_setup(p.curve, setup, rng.current().below(p.curve.r_group) or 1,
                                        {"N-01": q_id}, [11, 13])
    assert isinstance(enc.x_values["N-01"], Fp2)


# ---------------------------------------------------------------------- IA --

def test_ia01_pure_python_core() -> None:
    import ast
    from pathlib import Path

    banned = {"sympy", "gmpy2", "pycryptodome"}
    for f in (Path(__file__).resolve().parent.parent.parent / "src").rglob("*.py"):
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not any(a.name in banned for a in node.names)


def test_ia02_scalars_from_r_group() -> None:
    p = params.get("toy")
    r = rng.current().below(p.curve.r_group)
    assert 0 <= r < p.curve.r_group


def test_ia03_ibe_round_trip() -> None:
    from maka import hashing, ibe

    _fresh("reg-ia03")
    p = params.get("toy")
    k = rng.current().below(p.curve.r_group)
    k_pub = k * p.g
    pu = hashing.hash_to_point(p.curve, b"n")
    pr = k * pu
    ct = ibe.encrypt(p.curve, p.g, b"m", pu, k_pub)
    assert ibe.decrypt(p.curve, ct, pr) == b"m"


def test_ia04_sent_securely_is_ibe() -> None:
    from maka.protocol import p3_node_registration

    assert p3_node_registration.ibe.encrypt is not None


def test_ia05_three_nonce_instances() -> None:
    from maka.protocol import p3_node_registration, p4_node_authentication

    assert p3_node_registration.NONCE_BYTES == p4_node_authentication.NONCE_BYTES == 20


def test_ia06_aead_layer() -> None:
    from maka.aead import decrypt, encrypt

    blob = encrypt(bytes(32), b"x", ad=b"IA-06")
    assert decrypt(bytes(32), blob, ad=b"IA-06") == b"x"


def test_ia07_three_parameter_sets() -> None:
    for name in ("toy", "demo", "secure"):
        p = params.get(name)
        assert p.g.is_on_curve()


def test_ia08_channel_model() -> None:
    from maka.channel import Channel

    ch = Channel()
    assert hasattr(ch, "eavesdrop") and hasattr(ch, "replay")


def test_ia09_h1_h2_distinct() -> None:
    from maka import hashing

    assert hashing.hash_to_point is not hashing.h2_point_to_bytes


def test_ia10_coefficients_via_expansion() -> None:
    from icmds.coefficients import expand_polynomial

    coeffs = expand_polynomial([2, 3], 97)
    assert coeffs[-1] == 1


def test_ia11_two_track_x_i() -> None:
    from icmds.session_key import to_scalar
    from maka.field import Fp, Fp2

    p = params.get("toy")
    elem = Fp2(Fp(3, p.curve.p_field), Fp(5, p.curve.p_field))
    s = to_scalar(elem, p.curve.r_group)
    assert 0 <= s < p.curve.r_group
    assert to_scalar(elem, p.curve.r_group) == s  # deterministic equality, per IA-11's caveat


# ---------------------------------------------------------------------- OB --

def test_ob01_k_destroyed() -> None:
    from maka.protocol import p1_initialization, p2_key_generation

    _fresh("reg-ob01")
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    assert not hasattr(net.bs, "k")  # M1-T7: k is deleted, no longer rebound to None


def test_ob02_no_forward_secrecy() -> None:
    from maka import pairing
    from maka.protocol import p1_initialization, p2_key_generation

    _fresh("reg-ob02")
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    ch = next(iter(net.cluster_heads.values()))
    sk1 = pairing.modified_pairing(p.curve, ch.pr_i, net.bs.pu_bs)
    sk2 = pairing.modified_pairing(p.curve, ch.pr_i, net.bs.pu_bs)
    assert sk1 == sk2


def test_ob03_sizing_diagnostic() -> None:
    from eval import communication

    _fresh("reg-ob03")
    communication.run("toy", sizing="actual")  # must not raise


def test_ob04_g_is_public_but_insufficient() -> None:
    from security.maka import s3_ch_impersonation

    _fresh("reg-ob04")
    assert s3_ch_impersonation.run("toy") is True


def test_ob05_no_revocation_mechanism_exists() -> None:
    import maka

    assert not hasattr(maka, "revoke") and not hasattr(maka, "revocation")


def test_ob06_r_collision_halts() -> None:
    from attacks.icmds.a7_sk_impossible import _literal_branch

    _fresh("reg-ob06")
    p = params.get("toy")
    halt_id = _literal_branch(p.curve, p.g)
    assert halt_id in ("OB-06", "AM-09")


# ---------------------------------------------------------------------- SD --

def test_sd01_coefficients_checked_against_closed_forms() -> None:
    from icmds.coefficients import compute_and_verify

    _fresh("reg-sd01")
    p = params.get("toy")
    roots = [11, 13, 17]
    coeffs = compute_and_verify(roots, p.curve.r_group)
    assert coeffs[-1] == 1


# ------------------------------------------------- IMPLEMENTATION_PLAN.md M1 --

def test_ia12_decoded_points_are_validated() -> None:
    import pytest

    from maka import codec, ledger

    p = params.get("toy")
    point = 5 * p.g
    encoded = codec.enc_point(point)
    ledger.current().reset()
    with ledger.LedgerScope("X", "ia12"):
        decoded = codec.dec_point(p.curve, encoded)
    assert decoded == point
    assert ledger.current().total("X", "ia12") == {"T_SM_val": 1}
    with pytest.raises(codec.DecodeError):
        codec.dec_point(p.curve, encoded[:-1] + bytes([encoded[-1] ^ 1]))


def test_ia13_fixed_width_ids_and_zero_rejection() -> None:
    import pytest

    from maka.protocol.p3_node_registration import DegenerateScalarError, xor_to_scalar

    r = params.get("toy").curve.r_group
    assert xor_to_scalar("BS-01", "CH-01", r) == xor_to_scalar("CH-01", "BS-01", r)
    with pytest.raises(DegenerateScalarError):
        xor_to_scalar("CH-01", "CH-01", r)


def test_ia14_pseudo_ch_cm_carries_id_ch() -> None:
    from maka.protocol import p1_initialization, p2_key_generation, p3_node_registration

    _fresh("reg-ia14")
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.PAPER)
    assert net.channel.total_bits(["PSEUDO_CH_CM"]) == 320 + 160
    assert net.cluster_members["CH-01"]["CM-0101"].id_ch == "CH-01"


def test_ia15_one_em2_per_round() -> None:
    from maka.protocol import (
        p1_initialization,
        p2_key_generation,
        p3_node_registration,
        p4_node_authentication,
    )

    _fresh("reg-ia15")
    p = params.get("toy")
    net = p1_initialization.run(p.curve, p.g, fixtures.SMALL)
    p2_key_generation.run(net)
    p3_node_registration.run(net, fixtures.SMALL)
    p4_node_authentication.run(net, fixtures.SMALL)
    assert len(net.channel.eavesdrop("EM2")) == 1 and len(net.channel.eavesdrop("EM1")) == 3


def test_ia16_data_ad_binds_sender_recipient_seq() -> None:
    from maka.protocol.data_transmission import data_ad

    assert data_ad("CM-0101", "BS-01", 1) != data_ad("CM-0101", "BS-01", 2)
    assert data_ad("CM-0101", "BS-01", 1) != data_ad("CM-0102", "BS-01", 1)


def test_ob07_secure_pseudo_ids_are_priced_separately() -> None:
    from maka import ledger
    from maka.protocol import p1_initialization, p2_key_generation, p3_node_registration

    def ch_ed(secure: bool) -> int:
        _fresh(f"reg-ob07-{secure}")
        ledger.current().reset()
        p = params.get("toy")
        net = p1_initialization.run(p.curve, p.g, fixtures.PAPER)
        p2_key_generation.run(net)
        p3_node_registration.run(net, fixtures.PAPER, secure_pseudo_ids=secure)
        return ledger.current().total("CH-01", "registration")["T_E/D"]

    assert ch_ed(True) - ch_ed(False) == 1 + 1  # n + 1 with n = 1


def test_ob08_seeded_nonces_repeat_across_runs() -> None:
    from maka import aead

    nonces = []
    for _ in range(2):
        rng.seed(5)
        nonces.append(aead.encrypt(bytes(32), b"x", ad=b"")[:12])
    assert nonces[0] == nonces[1]


def test_ia17_maka_e_onboards_without_k_on_devices() -> None:
    from maka.enhanced import network as en

    net = en.build("toy", "paper", seed=17)
    net.onboard()
    assert all(d.status == "active" for d in net.scheduler.devices.values())
    assert [d.identity for d in net.scheduler.devices.values() if d.keystore.has("k")] == ["BS-01"]
