"""BAN idealisation and mechanised derivation of MAKA's §5.4 authentication exchange (P11.4).

Idealised messages (M1-M3) and assumptions (AS1-AS6) follow RP9 §6.2's idealisation of Fig. 3's
middle panel (node authentication). R1-R12 are the individual rule applications; no assumption
ablation is performed (that would be new analysis -- see docs/DEFERRED.md).
"""

from __future__ import annotations

from formal.ban.engine import Belief, Sees, apply, jurisdiction, message_meaning, nonce_verification
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


def derive() -> dict[int, Belief]:
    t = trace.active()
    t.banner("MAKA BAN derivation", "RP9 §6.2 idealisation of §5.4's node-authentication exchange")

    apply("R1 seeing", lambda: M1)
    r2 = apply("R2 message-meaning", message_meaning, M1, AS1)  # CM |= CH said {A1,A2,Nc_CH}
    r3 = apply("R3 nonce-verification", nonce_verification, r2, AS5, goal=3)  # CM |= CH |= (A1,A2,Nc_CH)
    r4 = apply("R4 jurisdiction", jurisdiction, AS4, r3, goal=1)  # CM |= (A1,A2,Nc_CH)  [Goal 1]

    apply("R5 seeing", lambda: M3)
    r6 = apply("R6 message-meaning", message_meaning, M3, AS3)  # CH |= CM said {A3,A4,Nc_CM}
    r7 = apply("R7 nonce-verification", nonce_verification, r6, AS6, goal=4)  # CH |= CM |= (A3,A4,Nc_CM)  [Goal 4]
    AS_CH_ctrl = Belief("CH", "CM controls (A3,A4)")
    r8 = apply("R8 jurisdiction", jurisdiction, AS_CH_ctrl, r7, goal=2)  # CH |= (A3,A4,Nc_CM)  [Goal 2]

    apply("R9 seeing", lambda: M2)
    r10 = apply("R10 message-meaning", message_meaning, M2, AS2)  # BS |= CH said {A1,A2,Nc_CH}
    AS_BS_fresh = Belief("BS", "fresh(Nc_CH)")
    r11 = apply("R11 nonce-verification", nonce_verification, r10, AS_BS_fresh)  # BS |= CH |= (A1,A2,Nc_CH)
    AS_BS_ctrl = Belief("BS", "CH controls (A1,A2)")
    apply("R12 jurisdiction", jurisdiction, AS_BS_ctrl, r11)  # BS |= (A1,A2,Nc_CH)

    return {1: r4, 2: r8, 3: r3, 4: r7}


def run() -> dict[int, bool]:
    goals = derive()
    results = {}
    t = trace.active()
    for goal_n, belief in goals.items():
        ok = belief is not None
        t.check(f"Goal {goal_n} reached: {belief!r}", ok, True, ok)
        results[goal_n] = ok
    all_ok = all(results.values())
    t.check("all four BAN goals reached (no assumption ablation performed)", all_ok, True, all_ok)
    return results
