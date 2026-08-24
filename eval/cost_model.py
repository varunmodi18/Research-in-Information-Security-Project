"""RP9 §7.1 cost-model constants (P12.1), each with its source.

All times in milliseconds, as published in RP9 Table 2's source constants (MICAz-class
sensor node benchmarks, as cited by RP9's own comparison baseline).
"""

from __future__ import annotations

T_HG = 12.419   # hash-to-point (map-to-point)
T_SM = 2.226    # elliptic-curve scalar multiplication
T_PA = 0.0288   # elliptic-curve point addition
T_ED = 3.85     # asymmetric encryption/decryption (Enc/Dec)
T_P = 5.811     # pairing computation
T_S = 0.0046    # symmetric encryption/decryption
T_H = 0.0023    # general-purpose hash
T_MAC = 0.0046  # MAC computation

ALL = {"T_HG": T_HG, "T_SM": T_SM, "T_PA": T_PA, "T_E/D": T_ED, "T_P": T_P,
       "T_S": T_S, "T_H": T_H, "T_MAC": T_MAC}
