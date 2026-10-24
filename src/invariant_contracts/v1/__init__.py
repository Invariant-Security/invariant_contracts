"""Contratos públicos congelados (versão 1).

Tudo neste pacote é contrato EXTERNO: a API /v1 que o cliente vendedor
consome e o evento de webhook.
Ao contrário dos modelos internos em `invariant_contracts.*` (que mudam junto
com o console), estes só mudam de forma aditiva — ver POLICY abaixo e o teste
de snapshot em tests/test_v1_contracts.py.
"""

from invariant_contracts.v1.api import (
    AssessmentEnvelope,
    AssessmentListItem,
    AssessmentRequest,
    DiscoveryHost,
    ErrorBody,
    ErrorCode,
    ErrorResponse,
    Finding,
    HostKeyObserved,
    ReportKind,
    ReportRequest,
    SSHCredentials,
    Summary,
    Target,
    TargetCreate,
)
from invariant_contracts.v1.webhook import (
    AssessmentCompletedData,
    ContainerRef,
    HostRef,
    WebhookEvent,
)

# Headers padronizados do /v1. X-Request-Id: aceito do cliente ou gerado;
# devolvido em toda resposta e em todo ErrorBody, e propagado
# gateway -> api -> serviços internos. Idempotency-Key: obrigatório para
# repetir com segurança POST de criação de alvo e de avaliação (24h).
REQUEST_ID_HEADER = "X-Request-Id"
IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"
API_KEY_SCOPES = (
    "targets:read",
    "targets:write",
    "discovery:run",
    "assessments:run",
    "assessments:read",
    "reports:generate",
)

POLICY = """\
Política de compatibilidade do /v1 (e do contrato de webhook):
- Só mudanças aditivas: campo novo opcional, rota nova, valor novo em enum
  documentado como extensível (ErrorCode).
- Clientes devem ignorar campos desconhecidos nas respostas.
- Remover, renomear ou mudar o tipo de um campo = nova versão (/v2).
- Depreciação anunciada com no mínimo 6 meses de antecedência.
- O /v1 não muda porque o console interno mudou: o console usa rotas internas.
- Credenciais SSH são somente entrada: nunca aparecem em resposta, log,
  persistência ou webhook.
- store_findings=false significa que achados não são persistidos nem
  temporariamente: depois da resposta da avaliação, findings=null com
  findings_omitted_reason="not_stored", e PDF por assessment_id devolve
  findings_not_stored.
"""

__all__ = [
    "API_KEY_SCOPES",
    "IDEMPOTENCY_KEY_HEADER",
    "REQUEST_ID_HEADER",
    "AssessmentCompletedData",
    "AssessmentEnvelope",
    "AssessmentListItem",
    "AssessmentRequest",
    "ContainerRef",
    "DiscoveryHost",
    "ErrorBody",
    "ErrorCode",
    "ErrorResponse",
    "Finding",
    "HostKeyObserved",
    "HostRef",
    "POLICY",
    "ReportKind",
    "ReportRequest",
    "SSHCredentials",
    "Summary",
    "Target",
    "TargetCreate",
    "WebhookEvent",
]
