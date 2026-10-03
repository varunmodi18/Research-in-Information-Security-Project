"""Password hashing, session tokens and the login rate limiter (IMPLEMENTATION_PLAN.md §4.5)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from maka.rng import SystemSource

_hasher = PasswordHasher()  # Argon2id
_DUMMY_HASH = _hasher.hash("timing-equaliser-not-a-password")
MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Constant work whether or not the user exists."""
    try:
        ok: bool = _hasher.verify(password_hash or _DUMMY_HASH, password)
        return ok and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def new_token(nbytes: int = 32) -> str:
    return base64.urlsafe_b64encode(SystemSource().bytes(nbytes)).decode().rstrip("=")


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


class LoginLimiter:
    """At most `max_failures` failed logins per username in `window_s`, then a `lock_s` lock."""

    def __init__(self, max_failures: int, window_s: int, lock_s: int,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.max_failures, self.window_s, self.lock_s = max_failures, window_s, lock_s
        self.clock = clock
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def locked(self, username: str) -> bool:
        with self._lock:
            return self._locked_until.get(username.lower(), 0.0) > self.clock()

    def record_failure(self, username: str) -> None:
        key, now = username.lower(), self.clock()
        with self._lock:
            q = self._failures[key]
            q.append(now)
            while q and q[0] < now - self.window_s:
                q.popleft()
            if len(q) >= self.max_failures:
                self._locked_until[key] = now + self.lock_s
                q.clear()

    def record_success(self, username: str) -> None:
        with self._lock:
            self._failures.pop(username.lower(), None)
