"""Configuration (IMPLEMENTATION_PLAN.md §4.9): environment variables prefixed MAKA_."""

from __future__ import annotations

import base64
import binascii
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from maka.rng import SystemSource

REPO_ROOT = Path(__file__).resolve().parents[2]


class SettingsError(RuntimeError):
    pass


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MAKA_", env_file=".env", extra="ignore")

    env: Literal["dev", "test", "demo"] = "dev"
    db_url: str = "sqlite:///./var/maka.db"
    kek: str | None = Field(default=None, repr=False)
    params_default: Literal["toy", "demo", "secure"] = "demo"
    max_pending: int = 16
    t_hs: int = 20
    t_retry: int = 5
    batch_steps: int = 5
    batch_max: int = 8
    bind: str = "127.0.0.1:8000"
    static_dir: Path = REPO_ROOT / "web" / "dist"
    session_idle_hours: float = 8.0
    login_max_failures: int = 5
    login_window_s: int = 15 * 60
    login_lock_s: int = 15 * 60
    persist_every_steps: int = 10
    demo_passwords_file: Path | None = None

    @field_validator("kek")
    @classmethod
    def _kek_is_32_bytes(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            raw = base64.b64decode(v, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("MAKA_KEK must be base64") from exc
        if len(raw) != 32:
            raise ValueError("MAKA_KEK must decode to 32 bytes")
        return v

    def kek_bytes(self) -> bytes:
        """The key-encryption key. Refuses to run without one unless MAKA_ENV=test, where an
        ephemeral KEK is generated (§4.4 rule 2)."""
        if self.kek is not None:
            return base64.b64decode(self.kek)
        if self.env == "test":
            if not hasattr(self, "_ephemeral_kek"):
                object.__setattr__(self, "_ephemeral_kek", SystemSource().bytes(32))
            return self._ephemeral_kek  # type: ignore[attr-defined,no-any-return]
        raise SettingsError("MAKA_KEK is required (32 random bytes, base64) unless MAKA_ENV=test")

    @property
    def secure_cookies(self) -> bool:
        host = self.bind.split(":")[0]
        return host not in ("127.0.0.1", "localhost", "::1")

    @property
    def allow_seeded_product(self) -> bool:
        return self.env != "demo"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
