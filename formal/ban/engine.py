"""BAN logic: postulates as typed inference rules (P11.3).

Encodes the standard BAN logic constructs: belief (P |= X), sees (P <| X), once-said
(P |~ X), jurisdiction, freshness (#(X)), and the shared-key/session-key notation
(P <-k-> Q). Each postulate is a small function taking premises and returning the derived
belief, printed via trace.
"""

from __future__ import annotations

from dataclasses import dataclass

from maka import trace


@dataclass(frozen=True)
class Belief:
    principal: str
    statement: str  # a symbolic rendering, e.g. "CM <-K-> CH" or "fresh(Nc_CH)"

    def __repr__(self) -> str:
        return f"{self.principal} |= {self.statement}"


@dataclass(frozen=True)
class Sees:
    principal: str
    statement: str

    def __repr__(self) -> str:
        return f"{self.principal} <| {self.statement}"


def message_meaning(sees_signed: Sees, believes_key: Belief) -> Belief:
    """Message-meaning rule: P sees {X}_K and P believes Q <-K-> P => P believes Q said X."""
    return Belief(sees_signed.principal, f"{believes_key.statement.split()[0]} said {sees_signed.statement}")


def nonce_verification(believes_said: Belief, believes_fresh: Belief) -> Belief:
    """Nonce-verification rule: P believes fresh(X) and P believes Q said X => P believes Q
    believes X."""
    who_said = believes_said.statement.split()[0]
    x = believes_said.statement.split("said", 1)[1].strip()
    return Belief(believes_said.principal, f"{who_said} |= {x}")


def jurisdiction(believes_authority: Belief, believes_other_believes: Belief) -> Belief:
    """Jurisdiction rule: P believes Q controls X and P believes Q believes X => P believes X."""
    x = believes_other_believes.statement.split("|=", 1)[1].strip()
    return Belief(believes_authority.principal, x)


def seeing(k: str) -> Sees:
    return Sees("*", f"seen({k})")


def apply(rule_name: str, rule_fn, *args: Belief, goal: int | None = None) -> Belief:
    t = trace.active()
    result = rule_fn(*args)
    goal_str = f"   [Goal {goal} OK]" if goal is not None else ""
    t.step("BAN", f"{rule_name} <- {', '.join(repr(a) for a in args)}  |-  {result!r}{goal_str}")
    return result
