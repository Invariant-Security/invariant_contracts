"""Assinatura de webhook: HMAC-SHA256 com timestamp, verificável pelo cliente
vendedor só com a biblioteca padrão."""

import hashlib
import hmac
import time

SIGNATURE_HEADER = "X-Invariant-Signature"
EVENT_ID_HEADER = "X-Invariant-Event-Id"
DELIVERY_ID_HEADER = "X-Invariant-Delivery-Id"
DEFAULT_TOLERANCE_S = 300


def sign_webhook(secret: str, body: bytes, timestamp: int | None = None) -> str:
    t = int(time.time()) if timestamp is None else timestamp
    mac = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={t},v1={mac}"


def verify_webhook(
    secret: str, body: bytes, header: str, tolerance_s: int = DEFAULT_TOLERANCE_S, now: int | None = None
) -> bool:
    """True se a assinatura confere e o timestamp está dentro da tolerância
    (protege contra reenvio de uma entrega antiga capturada)."""
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        t = int(parts["t"])
        given = parts["v1"]
    except (ValueError, KeyError):
        return False
    current = int(time.time()) if now is None else now
    if abs(current - t) > tolerance_s:
        return False
    expected = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, given)
