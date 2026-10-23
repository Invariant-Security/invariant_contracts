"""Exporta o JSON Schema de todos os contratos v1 — base do teste de
snapshot que impede mudança acidental do contrato.

Atualizar o snapshot (só quando a mudança for intencional e aditiva):
    python -m invariant_contracts.v1.schema_export > tests/snapshots/v1.json
"""

import json
import sys

from invariant_contracts import v1

MODELS = [
    v1.TargetCreate,
    v1.Target,
    v1.DiscoveryHost,
    v1.AssessmentRequest,
    v1.AssessmentEnvelope,
    v1.AssessmentListItem,
    v1.ReportRequest,
    v1.ErrorResponse,
    v1.WebhookEvent,
]


def export() -> dict:
    return {m.__name__: m.model_json_schema() for m in MODELS}


def main() -> None:
    json.dump(export(), sys.stdout, indent=2, sort_keys=True, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
