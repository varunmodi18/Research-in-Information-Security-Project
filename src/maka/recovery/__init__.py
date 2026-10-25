"""Operator-approved cluster-head replacement with a ranked recommendation (docs/RECOVERY.md, IA-20, IA-21).

Detection (the behaviour monitor flags a CH in k of the last m windows: a "CH suspected" alert, which
never acts) -> a ranked replacement recommendation among the cluster's members -> promotion of the
member the operator confirms (`EnhancedNetwork.promote`, no new keys). Tested, not statistically
evaluated.
"""
