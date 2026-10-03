"""API request/response schemas (IMPLEMENTATION_PLAN.md §4.5).

No schema has a field that could carry a key, scalar, password or keystore value (§4.4 rule 3).
Decrypted readings appear only in ReadingOut, served to Operator+ (FR-07).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

T = TypeVar("T")
NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$"

SECURITY_LEVELS = {
    "toy": "INSECURE: 24-bit group order, hand-checkable traces only",
    "demo": "about 60-bit security (512-bit F_p^2 discrete log), demonstration only",
    "secure": "about 80-bit security (1024-bit F_p^2 discrete log), demonstration only",
}


class Page(BaseModel, Generic[T]):
    items: list[T]
    next_cursor: int | None = None


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: Literal["admin", "operator", "viewer"]
    disabled: bool


class SessionInfoOut(BaseModel):
    user: UserOut
    role: str
    csrf_token: str


class CustomTopology(BaseModel):
    chs: int = Field(ge=1, le=5)
    cms_per_ch: int = Field(ge=1, le=8)


class NetworkCreate(BaseModel):
    name: str = Field(pattern=NAME_PATTERN)
    template: Literal["paper", "small", "net"] | None = "paper"
    custom: CustomTopology | None = None
    kind: Literal["product", "lab"] = "product"
    mode: Literal["enhanced", "original"] = "enhanced"
    params: Literal["toy", "demo", "secure"] = "demo"
    seed: int | None = Field(default=None, ge=0, le=2**62)
    secure_pseudo_ids: bool = True  # original mode only (I-02)
    forward_ciphertexts: bool = False  # original mode Lab variant (§4.7)


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    ident: str
    role: str
    cluster: str | None
    status: str
    epoch: int
    pu_fingerprint: str


class NetworkOut(BaseModel):
    id: int
    name: str
    kind: str
    mode: str
    params: str
    security_level: str
    template: str
    seed: int | None
    status: str
    step: int
    created_at: datetime
    status_counts: dict[str, int]
    device_count: int
    options: dict[str, Any] = {}


class NetworkDetail(NetworkOut):
    devices: list[DeviceOut]
    tunables: dict[str, int]


class NetworkDelete(BaseModel):
    confirm_name: str


class SessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    a: str
    b: str
    purpose: str
    state: str
    sid_hex: str
    established_step: int | None
    epoch: int
    sent: int
    recv: int
    superseded_by: str | None = None


class DeviceDetail(BaseModel):
    device: DeviceOut
    sessions: list[SessionOut]
    status_history: list[dict[str, Any]]


JobType = Literal["onboard", "step", "send_readings", "start_periodic", "stop_periodic", "rekey", "revoke",
                  "reprovision", "designate", "lab_scenario", "evaluation", "reset_network"]


class JobCreate(BaseModel):
    type: JobType
    args: dict[str, Any] = {}
    idempotency_key: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


class JobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    network_id: int | None
    type: str
    args: dict[str, Any] = Field(validation_alias="args_json")
    state: str
    progress: float
    phase: str
    result: dict[str, Any] | None = Field(default=None, validation_alias="result_json")
    error: str | None
    created_at: datetime
    finished_at: datetime | None


class JobAccepted(BaseModel):
    job_id: int
    created: bool


class CheckOut(BaseModel):
    name: str
    ok: bool
    reason: str = ""


class FrameOut(BaseModel):
    id: int
    frame_id: int
    job_id: int | None
    step: int
    sent_step: int
    src: str
    dst: str
    to: str | None
    label: str
    bytes_len: int
    paper_bits: int
    payload_hex: str | None
    verdict: str
    reason: str | None
    fate: str
    checks: list[CheckOut]


class EventOut(BaseModel):
    id: int
    network_id: int | None
    step: int
    ts: datetime
    severity: str
    type: str
    device: str
    peer: str | None
    session_sid: str | None
    frame_id: int | None
    details: dict[str, Any]


class ReadingOut(BaseModel):
    id: int
    device: str
    seq: int
    value: Any
    received_step: int


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,64}$")
    password: str = Field(min_length=12, max_length=256)
    role: Literal["admin", "operator", "viewer"]


class UserPatch(BaseModel):
    role: Literal["admin", "operator", "viewer"] | None = None
    disabled: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)


class ResetDemo(BaseModel):
    confirm: str

    @field_validator("confirm")
    @classmethod
    def _must_be_reset(cls, v: str) -> str:
        if v != "RESET":
            raise ValueError('type "RESET" to confirm')
        return v


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    action: str
    target: str
    ts: datetime
    outcome: str
