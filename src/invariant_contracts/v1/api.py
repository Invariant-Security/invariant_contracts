"""Modelos da API pública /v1 (gateway).

Nomes de campo próprios do /v1 (ex.: `control_id`, `private_key`) e não os
internos (`external_id`, `key_material`): o api traduz na fronteira, para que
uma mudança interna nunca vaze para o contrato.
"""

from datetime import datetime
from enum import Enum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, model_validator


class _Model(BaseModel):
    # forbid: o servidor nunca emite (nem aceita) campo fora do contrato.
    # Clientes, do lado deles, devem ignorar campos desconhecidos (POLICY).
    model_config = ConfigDict(extra="forbid")


class ErrorCode(str, Enum):
    """Códigos estáveis de erro. Extensível: valores novos podem surgir."""

    unauthorized = "unauthorized"
    forbidden_scope = "forbidden_scope"
    not_found = "not_found"
    validation_error = "validation_error"
    rate_limited = "rate_limited"
    idempotency_mismatch = "idempotency_mismatch"
    idempotency_in_progress = "idempotency_in_progress"
    license_required = "license_required"
    license_expired = "license_expired"
    license_revoked = "license_revoked"
    target_not_discovered = "target_not_discovered"
    ip_not_in_target = "ip_not_in_target"
    findings_not_stored = "findings_not_stored"
    ssh_auth_failed = "ssh_auth_failed"
    target_unreachable = "target_unreachable"
    assessment_timeout = "assessment_timeout"
    upstream_error = "upstream_error"
    internal_error = "internal_error"


class ErrorBody(_Model):
    code: ErrorCode
    message: str
    request_id: str


class ErrorResponse(_Model):
    error: ErrorBody


class TargetCreate(_Model):
    address: str = Field(description='IP único ("10.0.0.5") ou CIDR ("10.0.0.0/24")')
    label: str | None = Field(default=None, max_length=200)
    tags: list[str] = Field(default_factory=list, max_length=50)


class Target(_Model):
    id: int
    address: str
    label: str | None
    tags: list[str]
    created_at: datetime


DiscoveryClassification = Literal["windows", "linux", "docker", "waf", "firewall", "vmware", "unknown"]


class DiscoveryHost(_Model):
    ip: str
    classification: DiscoveryClassification
    confidence: float = Field(ge=0, le=1)
    scanned_at: datetime


_WRITE_ONLY = {"writeOnly": True}


class SSHCredentials(_Model):
    """SOMENTE ENTRADA. Usadas apenas durante a avaliação: nunca aparecem em
    resposta, log, persistência ou webhook. Nenhum modelo de saída do v1
    referencia este tipo (garantido por teste) e os segredos são excluídos
    de qualquer serialização (`model_dump`/`model_dump_json`)."""

    model_config = ConfigDict(extra="forbid", json_schema_extra=_WRITE_ONLY)

    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=256)
    auth_method: Literal["key", "password"]
    private_key: str | None = Field(default=None, repr=False, exclude=True, json_schema_extra=_WRITE_ONLY)
    password: str | None = Field(default=None, repr=False, exclude=True, json_schema_extra=_WRITE_ONLY)

    @model_validator(mode="after")
    def _exactly_one_secret(self) -> "SSHCredentials":
        if self.auth_method == "key" and (not self.private_key or self.password):
            raise ValueError("auth_method=key exige private_key e não aceita password")
        if self.auth_method == "password" and (not self.password or self.private_key):
            raise ValueError("auth_method=password exige password e não aceita private_key")
        return self


ReportKind = Literal["executive", "technical"]


class AssessmentRequest(_Model):
    ssh: SSHCredentials
    ip: IPvAnyAddress | None = Field(
        default=None,
        description="IP dentro do alvo (CIDR) e presente na última descoberta; omitido = primeiro descoberto",
    )


FindingResult = Literal["pass", "fail", "not_assessed", "not_applicable"]


class Finding(_Model):
    control_id: str
    title: str
    benchmark: str
    benchmark_version: str
    result: FindingResult
    level: int | None
    scored: bool | None
    evidence: str
    remediation: str
    collected_at: datetime


class Summary(_Model):
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    not_assessed: int = Field(ge=0)
    not_applicable: int = Field(ge=0)
    compliance_pct: int | None = Field(ge=0, le=100, description="None = nada aplicável foi avaliado")


FindingsOmittedReason = Literal["not_stored", "retention_expired"]


class AssessmentEnvelope(_Model):
    assessment_id: UUID
    target_id: int
    target_kind: Literal["linux_host"] = "linux_host"
    assessed_ip: str
    assessed_at: datetime
    source: Literal["console", "api"]
    summary: Summary
    findings: list[Finding] | None = Field(
        description="Presente na resposta da própria avaliação; depois, só se 'guardar achados' estiver "
        "ligado e dentro da retenção. null sempre acompanha findings_omitted_reason."
    )
    findings_omitted_reason: FindingsOmittedReason | None = Field(
        description="not_stored: 'guardar achados' desligado (inclusive em repetição por Idempotency-Key); "
        "retention_expired: guardados, mas já apagados pela retenção"
    )

    @model_validator(mode="after")
    def _findings_xor_reason(self) -> "AssessmentEnvelope":
        if (self.findings is None) == (self.findings_omitted_reason is None):
            raise ValueError("findings e findings_omitted_reason: exatamente um deve estar presente")
        return self


class AssessmentListItem(_Model):
    assessment_id: UUID
    target_id: int
    assessed_ip: str
    assessed_at: datetime
    source: Literal["console", "api"]
    summary: Summary
    findings_stored: bool


class ReportRequest(_Model):
    """Gera o PDF (resposta binária application/pdf) de uma avaliação já
    feita. Só funciona com 'guardar achados' ligado e os achados ainda dentro
    da retenção; senão ErrorCode.findings_not_stored. Com a opção desligada,
    os achados não são persistidos nem temporariamente."""

    assessment_id: UUID
    kind: ReportKind
