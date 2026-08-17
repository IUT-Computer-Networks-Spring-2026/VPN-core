
import datetime as _dt
import functools
import os
from typing import Callable, Dict, Optional

import jwt
from flask import request, jsonify, g

JWT_SECRET = os.environ.get("VPN_JWT_SECRET", "change-me-vpn-core-dev-secret-0123456789abcdef")
JWT_ALGO = "HS256"

TOKEN_TTL_NORMAL = _dt.timedelta(hours=24)
TOKEN_TTL_REMEMBER = _dt.timedelta(days=30)


def issue_token(username: str, is_admin: bool, remember: bool = False) -> str:
    """Create a signed JWT for the given identity."""
    ttl = TOKEN_TTL_REMEMBER if remember else TOKEN_TTL_NORMAL
    now = _dt.datetime.now(_dt.timezone.utc)
    payload = {
        "username": username,
        "is_admin": bool(is_admin),
        "iat": now,
        "exp": now + ttl,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def decode_token(token: str) -> Optional[Dict]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.PyJWTError:
        return None


def _extract_token() -> Optional[str]:
    """Read the JWT from Authorization: Bearer, or the `token` cookie."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return request.cookies.get("token")


def jwt_required(admin_only: bool = False) -> Callable:
    """Decorator: require a valid JWT (optionally an admin token)."""
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            token = _extract_token()
            payload = decode_token(token) if token else None
            if payload is None:
                return jsonify({"error": "Authentication required"}), 401
            if admin_only and not payload.get("is_admin"):
                return jsonify({"error": "Admin privileges required"}), 403
            g.jwt = payload
            g.username = payload.get("username")
            g.is_admin = bool(payload.get("is_admin"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def human_bytes(n: Optional[int]) -> str:
    """Format a byte count as a human-readable string."""
    try:
        n = int(n or 0)
    except (TypeError, ValueError):
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(n)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{n} B"
