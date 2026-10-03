"""Which job types each network kind, mode and role may run (§4.5, NFR-SEC-03, V-WEB-06)."""

from __future__ import annotations

from maka_server import models
from maka_server.errors import ApiError

LAB_ONLY = {"lab_scenario", "evaluation"}
ADMIN_ONLY: set[str] = set()


def check_job_allowed(net: models.Network, job_type: str, role: str) -> None:
    if job_type in LAB_ONLY and net.kind != "lab":
        raise ApiError(422, "MODE_NOT_ALLOWED", "Mode not allowed",
                       f"{job_type} jobs run only on lab networks (NFR-SEC-03)")
    if job_type in ADMIN_ONLY and role != "admin":
        raise ApiError(403, "FORBIDDEN", "Insufficient role", f"{job_type} requires admin")
    if net.status == "busy" and job_type == "reset_network":
        raise ApiError(409, "NETWORK_BUSY", "Network busy", "wait for the running job to finish")
