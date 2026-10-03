"""Bytes-only device runtime (IMPLEMENTATION_PLAN.md §4.3, M2).

Devices exchange serialised frames over a Bus driven by a discrete-event Scheduler. A device
holds no reference to any other device, the bus, the scheduler or the network, so one device
can learn about another only from bytes it receives (the structural fix for I-01..I-04).
"""
