"""S1: `maka primitives --params toy -vvv` -- curve, the seven pairing tests (including the
ER-03 pair), hash-to-point, IBE round trip. Hand-checkable at `toy`.

Realises: PLAN.md P4.6.
"""

from __future__ import annotations

from maka import hashing, ibe, pairing, params, rng, trace


def run(params_name: str = "demo", verbosity: int = 2) -> None:
    t = trace.active()
    t.banner("D1 -- Primitives", f"RP9 sect 2.1-2.2 preliminaries, instantiated per IA-02/IA-03/IA-06/IA-09")
    p = params.get(params_name)
    c, g = p.curve, p.g

    t.section(1, "Curve report")
    t.value("p_field", c.p_field, note=f"{c.p_field.bit_length()} bits")
    t.value("curve", f"y^2 = x^3 + {c.a}*x + {c.b}")
    t.value("#E(F_p_field)", c.order)
    t.value("r_group", c.r_group, note=f"{c.r_group.bit_length()} bits, prime subgroup order")
    t.value("cofactor", c.cofactor)
    t.value("g", g)
    t.check("g is on curve", g.is_on_curve(), True, g.is_on_curve())
    t.check("r_group * g = O", (c.r_group * g).is_infinity(), True, (c.r_group * g).is_infinity())
    if p.insecure:
        t.register("IA-07", f"parameter set '{params_name}' is INSECURE by construction -- demonstration only")

    t.section(2, "Pairing self-test (P3.4)")
    results = pairing.selftest(c, g)
    t.table(["#", "property", "verdict"],
            [[n, name, "PASS" if ok else "FAIL"] for n, name, ok in results],
            "Seven pairing properties")

    t.section(3, "Hash-to-point (IA-09)")
    point = hashing.hash_to_point(c, b"demo-identity")
    t.value("H('demo-identity')", point)
    encoded = hashing.h2_point_to_bytes(point, nbytes=20)
    t.value("H2(point)", encoded)

    t.section(4, "IBE round trip (IA-03)")
    k = rng.current().below(c.r_group)
    k_pub = k * g
    t.value("K_pub = k*g", k_pub, note="[IA-03 scaffolding -- not part of RP9's parameter set]")
    pu_i = hashing.hash_to_point(c, b"node-demo")
    pr_i = k * pu_i
    ciphertext = ibe.encrypt(c, g, b"MAKA primitive demo payload", pu_i, k_pub)
    plaintext = ibe.decrypt(c, ciphertext, pr_i)
    t.check("Dec(Enc(m, Pu_i), Pr_i) == m", plaintext == b"MAKA primitive demo payload",
            b"MAKA primitive demo payload", plaintext)

    wrong_pr = (k + 1) * pu_i
    try:
        ibe.decrypt(c, ciphertext, wrong_pr)
        t.check("wrong-key decryption fails", False, "raises", "did not raise")
    except Exception as exc:  # noqa: BLE001 -- deliberately broad: any AEAD failure is the point
        t.check("wrong-key decryption fails", True, "raises", type(exc).__name__)


if __name__ == "__main__":
    trace.init(run_id="d1-standalone", verbosity=2)
    rng.seed(0)
    run(params_name="toy", verbosity=3)
