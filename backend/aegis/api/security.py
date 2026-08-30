"""Authentication, authorization and audit primitives.

RBAC roles (least privilege):
  * viewer   — read incidents, graph, overview
  * analyst  — viewer + run investigations, ask the copilot, update incident status
  * admin    — analyst + manage rules/threat-intel, run the simulator, read the audit log
  * ingestor — machine role (API key) that may only POST events

Auth is JWT (HS256) for humans and a static API key for the ingest pipeline. Passwords are pbkdf2_sha256.
Everything security-relevant is written to the audit log.
"""

from __future__ import annotations

import hmac
import time
from datetime import UTC, datetime, timedelta
from enum import IntEnum

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from aegis.config import get_settings

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
bearer = HTTPBearer(auto_error=False)


class Role(IntEnum):
    VIEWER = 10
    ANALYST = 20
    ADMIN = 30
    INGESTOR = 5  # machine role, orthogonal but low read scope


ROLE_NAMES = {"viewer": Role.VIEWER, "analyst": Role.ANALYST, "admin": Role.ADMIN, "ingestor": Role.INGESTOR}


class User(BaseModel):
    username: str
    role: str
    tenant_id: str = "default"

    @property
    def level(self) -> int:
        return int(ROLE_NAMES.get(self.role, Role.VIEWER))


# ------------------------------------------------------------------ password + token
def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(pw, hashed)
    except Exception:
        return False


def create_token(user: User) -> str:
    s = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": user.username,
        "role": user.role,
        "tenant": user.tenant_id,
        "iat": now,
        "exp": now + timedelta(minutes=s.jwt_expiry_minutes),
    }
    return jwt.encode(payload, s.jwt_secret, algorithm=s.jwt_algorithm)


def decode_token(token: str) -> User:
    s = get_settings()
    try:
        payload = jwt.decode(token, s.jwt_secret, algorithms=[s.jwt_algorithm])
    except JWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token") from exc
    return User(username=payload["sub"], role=payload.get("role", "viewer"), tenant_id=payload.get("tenant", "default"))


# ------------------------------------------------------------------ dependencies
async def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> User:
    if creds is None or not creds.credentials:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    return decode_token(creds.credentials)


def require_role(minimum: Role):
    async def _dep(user: User = Depends(current_user)) -> User:
        if user.level < int(minimum):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"requires role >= {minimum.name.lower()}")
        return user

    return _dep


def require_api_key(request: Request) -> str:
    """Constant-time comparison of the ingest API key."""
    s = get_settings()
    provided = request.headers.get("x-api-key", "")
    expected = s.ingest_api_key
    if not hmac.compare_digest(provided.encode(), expected.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid ingest API key")
    return provided


# ------------------------------------------------------------------ simple in-memory user store
class UserStore:
    def __init__(self) -> None:
        s = get_settings()
        self._users: dict[str, tuple[str, str]] = {}  # username -> (hash, role)
        self.add(s.admin_username, s.admin_password, "admin")
        # demo accounts so the platform is usable out of the box (documented in README)
        self.add("analyst", "analyst", "analyst")
        self.add("viewer", "viewer", "viewer")

    def add(self, username: str, password: str, role: str) -> None:
        self._users[username] = (hash_password(password), role)

    def authenticate(self, username: str, password: str) -> User | None:
        rec = self._users.get(username)
        if rec and verify_password(password, rec[0]):
            return User(username=username, role=rec[1])
        return None


# ------------------------------------------------------------------ token-bucket rate limiter
class RateLimiter:
    def __init__(self, per_minute: int):
        self.capacity = per_minute
        self.refill = per_minute / 60.0
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.get(key, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self.refill)
        if tokens < cost:
            self._buckets[key] = (tokens, now)
            return False
        self._buckets[key] = (tokens - cost, now)
        return True
