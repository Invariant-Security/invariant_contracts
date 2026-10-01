"""Evento de webhook entregue ao cliente vendedor.

Headers de cada entrega:
- X-Invariant-Event-Id: igual ao `id` do corpo; o MESMO em todas as
  retentativas (use para deduplicar — a entrega é "pelo menos uma vez").
- X-Invariant-Delivery-Id: único por tentativa de entrega.
- X-Invariant-Signature: "t=<unix>,v1=<hex>", HMAC-SHA256(segredo,
  f"{t}.{corpo_bruto}") — ver invariant_contracts.webhook_signature.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from invariant_contracts.v1.api import Summary


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HostRef(_Model):
    kind: Literal["linux_host"] = "linux_host"
    target_id: int
    address: str
    assessed_ip: str


class ContainerRef(_Model):
    kind: Literal["docker_container"] = "docker_container"
    name: str


class AssessmentCompletedData(_Model):
    source: Literal["console", "api"]
    assessment_id: UUID | None = Field(description="null para container (não há id persistido)")
    target: HostRef | ContainerRef = Field(discriminator="kind")
    summary: Summary


class WebhookEvent(_Model):
    id: UUID
    type: Literal["assessment.completed"]
    created_at: datetime
    installation_id: UUID
    data: AssessmentCompletedData
