"""Experimental behavioural monitoring (docs/BEHAVIOUR.md, register IA-19).

MAKA-E establishes WHO a device is. This package looks at how authenticated devices BEHAVE, from
data the base station already records (frames and security events), and raises alerts on
abnormal device behaviour. It never revokes, rekeys or blocks anything. Its data come from our
own simulator with injected faults, so its results do not transfer to real deployments.

`traffic`, `features` and `dataset` are pure Python. `detectors` and `evaluate` need the optional
`[ml]` extra (numpy, scikit-learn); the cryptographic core never imports them (IA-18).
"""
