"""Protocolo appliance ↔ central de licenças.

Um único POST /v1/sync: ativar = sync sem uso. O uso viaja como hashes
HMAC dos hosts (nunca IP/nome em claro) — reenvio é idempotente porque a
central guarda a união dos conjuntos.
"""

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

HOST_HASH_PATTERN = r"^[0-9a-f]{64}$"
PERIOD_PATTERN = r"^\d{4}-(0[1-9]|1[0-2])$"
MAX_HASHES_PER_SYNC = 50_000


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


LicenseKind = Literal["direct", "partner", "internal"]
HostKind = Literal["linux_host", "docker_container"]


class LicensingErrorCode(str, Enum):
    """Extensível: valores novos podem surgir."""

    license_invalid = "license_invalid"
    license_revoked = "license_revoked"
    installation_deactivated = "installation_deactivated"
    installation_limit = "installation_limit"
    installation_conflict = "installation_conflict"
    period_out_of_window = "period_out_of_window"
    payload_too_large = "payload_too_large"
    validation_error = "validation_error"


class UsageBatch(_Model):
    period: str = Field(pattern=PERIOD_PATTERN, description="Mês civil UTC, YYYY-MM")
    host_kind: HostKind
    host_hashes: list[Annotated[str, StringConstraints(pattern=HOST_HASH_PATTERN)]] = Field(
        description="HMAC-SHA256 hex de cada host distinto"
    )


class SyncRequest(_Model):
    license_key: str = Field(min_length=10, max_length=200)
    installation_id: UUID
    hostname: str | None = Field(default=None, max_length=255)
    app_version: str | None = Field(default=None, max_length=50)
    usage: list[UsageBatch] = Field(default_factory=list)


class CertificatePayload(_Model):
    """Conteúdo assinado (Ed25519) do certificado. Formato do token:
    base64url(json canônico) + "." + base64url(assinatura)."""

    v: Literal[1] = 1
    kid: str = Field(description="Identifica a chave de assinatura (rotação)")
    license_id: str
    holder: str
    kind: LicenseKind
    installation_id: UUID
    issued_at: datetime
    expires_at: datetime
    bill_containers: bool


class SyncResponse(_Model):
    certificate: str
    server_time: datetime
    stored: dict[str, dict[HostKind, int]] = Field(
        description="Contagem de hosts distintos guardada por período e tipo, após este sync"
    )


class LicensingError(_Model):
    code: LicensingErrorCode
    message: str
    request_id: str
