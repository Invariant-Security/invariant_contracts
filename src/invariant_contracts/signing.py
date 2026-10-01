"""Formatos de assinatura compartilhados (sem criptografia assimétrica aqui).

- Webhook: HMAC-SHA256 com timestamp, verificável pelo cliente vendedor só
  com a biblioteca padrão.
- Certificado de licença: só o envelope (JSON canônico + base64url); a
  assinatura Ed25519 em si fica com quem tem a chave (central assina,
  appliance verifica).
"""

import base64
import hashlib
import hmac
import json
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


def canonical_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def encode_certificate(payload_bytes: bytes, signature: bytes) -> str:
    return f"{b64url_encode(payload_bytes)}.{b64url_encode(signature)}"


def split_certificate(token: str) -> tuple[bytes, bytes]:
    """Separa (payload_bytes, assinatura). Não verifica nada — quem chama
    verifica a assinatura sobre exatamente estes bytes antes de confiar."""
    payload_part, sig_part = token.split(".")
    return b64url_decode(payload_part), b64url_decode(sig_part)
