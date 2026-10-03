"""ICMDS RP9 §3 steps 1-4: pre-distributed keys, beacon, BS key generation, CH re-check.

Scope bound: implements RP9's summary of ICMDS, not ICMDS-P's fuller Steps 1-8 (hop counts,
residual-energy CH election, recovery) -- RP9 explicitly excludes CH selection and recovery
from its review, so those are out of scope (see docs/SOURCES.md).
"""

from __future__ import annotations

from dataclasses import dataclass

from maka import trace


@dataclass
class IcmdsNode:
    identity: str
    distance_from_bs: int
    public_key: tuple[str, int, bytes]  # (ID, distance, BS stamp)


def bs_generate_public_key(node_id: str, distance: int, bs_stamp: bytes) -> IcmdsNode:
    """Step 3: BS generates a public key (ID, distance from BS, BS stamp) per node."""
    t = trace.active()
    node = IcmdsNode(identity=node_id, distance_from_bs=distance, public_key=(node_id, distance, bs_stamp))
    t.value(f"pubkey({node_id})", node.public_key)
    return node


def ch_recheck_public_key(node: IcmdsNode, expected_distance: int) -> bool:
    """Step 4: CH re-checks the public key using addition and multiplication only."""
    t = trace.active()
    ok = node.public_key[1] == expected_distance
    t.check(f"CH re-check of {node.identity}'s public key", ok, expected_distance, node.public_key[1])
    return ok
