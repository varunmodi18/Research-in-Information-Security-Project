"""BAN idealisation and mechanised derivation of MAKA's §5.4 authentication exchange (P11.4).

Idealised messages (M1-M3) and assumptions (AS1-AS6) follow RP9 §6.2's idealisation of Fig. 3's
middle panel (node authentication). R1-R12 are the individual rule applications; no assumption
ablation is performed (that would be new analysis -- see docs/DEFERRED.md).

Each goal is checked against RP9's goal *statement* (IMPLEMENTATION_PLAN.md M1-T9, I-12):
a goal is REACHED only if the derivation produced exactly the expected belief. RP9's Goals 1-2
concern the session key SK_BS-CH = e(Pu_CH, Pr_BS), which is computed offline from static
keys and never appears in any message, so no BAN rule derives a belief about it: they are
reported UNREACHABLE. Note also that the message-meaning steps apply to encryption under the
*receiver's* public key, which in BAN gives no evidence of origin; the derivation reproduces
RP9's steps as published (see IMPLEMENTATION_PLAN.md §1.2 S7).
"""

from __future__ import annotations

from formal.ban.engine import (
    Belief,
    Sees,
    apply,
    jurisdiction,
    message_meaning,
    nonce_verification,
    session_key_rule,
)
from maka import trace

# Idealised messages, per RP9 §6.2's notation
M1 = Sees("CM", "{A1,A2,Nc_CH}_Pu_CM")  # EM1: CH -> CM
M2 = Sees("BS", "{A1,A2,Nc_CH}_Pu_BS")  # EM2: CH -> BS
M3 = Sees("CH", "{A3,A4,Nc_CM}_Pu_CH")  # EM3: CM -> CH

# Assumptions AS1-AS6
AS1 = Belief("CM", "CH <-Pu_CM-> CM")  # CM believes the key used to seal EM1 is shared with CH
AS2 = Belief("BS", "CH <-Pu_BS-> BS")
AS3 = Belief("CH", "CM <-Pu_CH-> CH")
AS4 = Belief("CM", "CH controls (A1,A2)")  # CM believes CH has jurisdiction over the ephemerals it picks
AS5 = Belief("CM", "fresh(Nc_CH)")
AS6 = Belief("CH", "fresh(Nc_CM)")

# SK_BS-CH = e(Pu_CH, Pr_BS): its inputs are static keys only (RP9 §5.5).
SK_INPUTS = frozenset({"Pu_CH", "Pr_BS"})

# RP9 §6.2's goals, as stated.
EXPECTED: dict[int, Belief] = {
    1: Belief("BS", "BS <-SK-> CH"),
    2: Belief("BS", "CH |= BS <-SK-> CH"),
    3: Belief("CM", "CH |= (A1,A2,Nc_CH)"),
    4: Belief("CH", "CM |= (A3,A4,Nc_CM)"),
}
REACHED = "REACHED"
UNREACHABLE = "UNREACHABLE (no BAN rule derives beliefs about an offline-computed key)"
NOT_REACHED = "NOT REACHED (derived belief differs from the goal statement)"


def derive() -> list[Belief]:
    """Applies R1-R12 and returns every belief derived."""
    t = trace.active()
    t.banner("MAKA BAN derivation", "RP9 §6.2 idealisation of §5.4's node-authentication exchange")
    derived: list[Belief | None] = []

    apply("R1 seeing", lambda: M1)
    r2 = apply("R2 message-meaning", message_meaning, M1, AS1)  # CM |= CH said {A1,A2,Nc_CH}
    r3 = apply("R3 nonce-verification", nonce_verification, r2, AS5)  # CM |= CH |= (A1,A2,Nc_CH)
    r4 = apply("R4 jurisdiction", jurisdiction, AS4, r3)  # CM |= (A1,A2,Nc_CH)
    derived += [r2, r3, r4]

    apply("R5 seeing", lambda: M3)
    r6 = apply("R6 message-meaning", message_meaning, M3, AS3)  # CH |= CM said {A3,A4,Nc_CM}
    r7 = apply("R7 nonce-verification", nonce_verification, r6, AS6)  # CH |= CM |= (A3,A4,Nc_CM)
    as_ch_ctrl = Belief("CH", "CM controls (A3,A4)")
    r8 = apply("R8 jurisdiction", jurisdiction, as_ch_ctrl, r7)  # CH |= (A3,A4,Nc_CM)
    derived += [r6, r7, r8]

    apply("R9 seeing", lambda: M2)
    r10 = apply("R10 message-meaning", message_meaning, M2, AS2)  # BS |= CH said {A1,A2,Nc_CH}
    as_bs_fresh = Belief("BS", "fresh(Nc_CH)")
    r11 = apply("R11 nonce-verification", nonce_verification, r10, as_bs_fresh)  # BS |= CH |= (A1,A2,Nc_CH)
    as_bs_ctrl = Belief("BS", "CH controls (A1,A2)")
    r12 = apply("R12 jurisdiction", jurisdiction, as_bs_ctrl, r11)  # BS |= (A1,A2,Nc_CH)
    derived += [r10, r11, r12]

    # RP9's R8/R9 (its numbering): the session-key rule on BS |= CH |= (..Nc_CH..) is meant to
    # give Goal 1, but SK_BS-CH does not depend on any component of that message.
    sk = apply("RP9 R8 session-key rule (for Goal 1)", session_key_rule, as_bs_fresh, r11, "SK", SK_INPUTS)
    derived.append(sk)
    return [b for b in derived if b is not None]


def verdicts(derived: list[Belief], expected: dict[int, Belief] | None = None) -> dict[int, str]:
    expected = EXPECTED if expected is None else expected
    out = {}
    for goal, belief in expected.items():
        if belief in derived:
            out[goal] = REACHED
        elif "<-SK->" in belief.statement:
            out[goal] = UNREACHABLE
        else:
            out[goal] = NOT_REACHED
    return out


def run() -> dict[int, str]:
    t = trace.active()
    derived = derive()
    results = verdicts(derived)
    for goal, verdict in results.items():
        t.check(f"Goal {goal}: {EXPECTED[goal]!r} -> {verdict}", verdict == REACHED, REACHED, verdict)
    t.table(["goal", "statement (RP9 §6.2)", "verdict"],
            [[g, repr(EXPECTED[g]), v] for g, v in results.items()], "BAN goals")
    return results
