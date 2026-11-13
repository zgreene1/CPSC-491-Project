"""Minimal authentication for api_server.py — SOC 2 CC6.1 (Logical Access Security).

Scope is intentionally capstone-appropriate, not production-grade: there is
no user database anywhere in this project, so this supports a single
configured demo account via environment variables rather than a real user
store. Tokens are self-contained and signed (HMAC-SHA256 over a small JSON
payload) rather than backed by a session store/database, so verification
needs no persistence beyond an in-memory logout blocklist — consistent with
the rest of api_server.py, which already keeps scan state in memory only.

This module only issues and verifies tokens. Whether the scan endpoints in
api_server.py actually *require* a valid token is controlled separately by
the REQUIRE_AUTH environment variable (see api_server.py) — this lets the
auth system be real and fully tested without breaking any existing
unauthenticated workflow until the team is ready to turn it on.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Optional

DEFAULT_TOKEN_TTL_SECONDS = 3600

# A fresh random secret is generated per process if AUTH_SECRET isn't set.
# That's fine for a single-process demo (tokens just stop verifying across a
# restart, which only means affected users have to log in again) and avoids
# ever committing a real secret to the repo.
_SECRET = os.environ.get("AUTH_SECRET")
if not _SECRET:
    _SECRET = secrets.token_hex(32)
    print(
        "[auth] AUTH_SECRET not set — generated a random secret for this process. "
        "Existing tokens will stop verifying if the server restarts. Set AUTH_SECRET "
        "to a stable value to avoid that.",
    )

_blocklist: set[str] = set()


class AuthError(Exception):
    """Raised for any authentication failure. str(err) is the user-facing message."""


def _sign(payload_b64: str) -> str:
    signature = hmac.new(_SECRET.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256)
    return base64.urlsafe_b64encode(signature.digest()).decode("ascii").rstrip("=")


def verify_credentials(username: str, password: str) -> bool:
    """Timing-safe comparison against the single configured demo account."""
    expected_username = os.environ.get("AUTH_USERNAME", "analyst")
    expected_password = os.environ.get("AUTH_PASSWORD", "vulnscan-demo")

    # Both comparisons always run (no short-circuit on username) so a wrong
    # username doesn't return faster than a wrong password.
    username_ok = hmac.compare_digest(username, expected_username)
    password_ok = hmac.compare_digest(password, expected_password)
    return username_ok and password_ok


def issue_token(username: str, ttl_seconds: Optional[int] = None) -> tuple[str, int]:
    """Returns (token, expires_at_unix_seconds)."""
    ttl = ttl_seconds if ttl_seconds is not None else int(
        os.environ.get("AUTH_TOKEN_TTL_SECONDS", DEFAULT_TOKEN_TTL_SECONDS),
    )
    expires_at = int(time.time()) + ttl

    # jti makes every issued token unique even if two logins for the same
    # user happen within the same second (same username + same exp would
    # otherwise collide byte-for-byte, and logging out one would silently
    # log out the other too).
    payload = json.dumps(
        {"sub": username, "exp": expires_at, "jti": secrets.token_hex(8)},
        separators=(",", ":"),
    ).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    signature = _sign(payload_b64)

    return f"{payload_b64}.{signature}", expires_at


def verify_token(token: Optional[str]) -> str:
    """Returns the username if the token is valid, unexpired, and not
    logged out. Raises AuthError otherwise."""
    if not token:
        raise AuthError("Missing authentication token.")

    if token in _blocklist:
        raise AuthError("This session has been logged out.")

    try:
        payload_b64, signature = token.split(".", 1)
    except ValueError:
        raise AuthError("Malformed authentication token.") from None

    expected_signature = _sign(payload_b64)
    if not hmac.compare_digest(signature, expected_signature):
        raise AuthError("Invalid authentication token.")

    try:
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        username = payload["sub"]
        expires_at = payload["exp"]
    except Exception:
        raise AuthError("Invalid authentication token.") from None

    if not isinstance(username, str) or not isinstance(expires_at, int):
        raise AuthError("Invalid authentication token.")

    if time.time() >= expires_at:
        raise AuthError("Session has expired.")

    return username


def invalidate_token(token: str) -> None:
    """Blocklists a token so it fails verification even before it expires."""
    _blocklist.add(token)


def extract_bearer_token(authorization_header: Optional[str]) -> Optional[str]:
    if not authorization_header:
        return None
    prefix = "Bearer "
    if not authorization_header.startswith(prefix):
        return None
    return authorization_header[len(prefix):].strip() or None
