"""MAKA-E v1: the enhanced protocol (IMPLEMENTATION_PLAN.md §2.3, §4.6, M4).

RP9's identity-based key material (Pr_i = k*H(ID_i)) with: provisioning without k on devices
(C1), pairwise PSKs from SOK key agreement (C2), a PSK-authenticated ephemeral-DH key exchange
modelled on TLS 1.3 psk_dhe_ke (C3), and BS-authorised membership, designation, revocation and
authenticated batching (C4).
"""
