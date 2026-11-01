"""HMAC request signing for Brain -> Chamber calls (BUILD_PLAN §3)."""

import hashlib
import hmac
import time

TIMESTAMP_HEADER = "X-Detonator-Timestamp"
SIGNATURE_HEADER = "X-Detonator-Signature"
MAX_SKEW_S = 300


def sign(secret: str, timestamp: int, body: bytes) -> str:
    message = f"{timestamp}.".encode() + body
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def signed_headers(secret: str, body: bytes, now: int | None = None) -> dict[str, str]:
    timestamp = int(time.time()) if now is None else now
    return {
        TIMESTAMP_HEADER: str(timestamp),
        SIGNATURE_HEADER: sign(secret, timestamp, body),
    }


def verify(
    secret: str,
    timestamp_header: str | None,
    signature_header: str | None,
    body: bytes,
    now: int | None = None,
) -> bool:
    if not secret or not timestamp_header or not signature_header:
        return False
    try:
        timestamp = int(timestamp_header)
    except ValueError:
        return False
    current = int(time.time()) if now is None else now
    if abs(current - timestamp) > MAX_SKEW_S:
        return False
    return hmac.compare_digest(sign(secret, timestamp, body), signature_header)
