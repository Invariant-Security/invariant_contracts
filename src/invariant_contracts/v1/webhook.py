"""Evento de webhook entregue ao cliente vendedor.

Headers de cada entrega:
- X-Invariant-Event-Id: igual ao `event_id` do corpo; o MESMO em todas as
  retentativas (use para deduplicar — a entrega é "pelo menos uma vez").
- X-Invariant-Delivery-Id: único por tentativa de entrega.
- X-Invariant-Signature: "t=<unix>,v1=<hex>", HMAC-SHA256(segredo,
  f"{t}.{corpo_bruto}") — ver invariant_contracts.signing.
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
    """Só o resumo — nunca achados, evidência ou credenciais."""

    source: Literal["console", "api"]
    target: HostRef | ContainerRef = Field(discriminator="kind")
    summary: Summary


class WebhookEvent(_Model):
    event_id: UUID = Field(description="Imutável: o mesmo em todas as retentativas (deduplique por ele)")
    event_type: Literal["assessment.completed"]
    schema_version: Literal[1] = 1
    occurred_at: datetime = Field(description="Quando a avaliação terminou")
    installation_id: UUID
    assessment_id: UUID = Field(description="Sempre presente; para container é gerado na conclusão")
    data: AssessmentCompletedData
