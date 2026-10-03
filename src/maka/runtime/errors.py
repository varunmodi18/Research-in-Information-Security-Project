"""Runtime exceptions (IMPLEMENTATION_PLAN.md §4.3)."""

from __future__ import annotations


class RuntimeFault(Exception):
    """Base class for runtime errors."""


class StepLimitExceeded(RuntimeFault):
    """run_until_quiescent() reached max_steps with work still pending."""


class AdversaryNotAllowed(RuntimeFault):
    """An interceptor was added to a product network's bus (NFR-SEC-03, V-WEB-06)."""


class UnknownDevice(RuntimeFault):
    """A command named a device the scheduler does not run."""


class KeystoreError(RuntimeFault):
    """Missing entry, wrong class, or a destroyed secret was requested."""


class ModeNotAllowed(RuntimeFault):
    """Original (RP9) mode or Lab adversaries requested on a product network (NFR-SEC-03)."""
