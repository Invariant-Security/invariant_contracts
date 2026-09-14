from typing import Literal

from pydantic import BaseModel


class Finding(BaseModel):
    """Campos exatos de invariant.assessment.Finding -- o resultado final
    de uma avaliação, sem alterar nenhum campo do dataclass original.
    """

    target: str
    external_id: str
    status: str  # "PASS" ou "FAIL"
    control_title: str
    source_name: str
    document_name: str
    document_version: str
    evidence_output: str
    collected_at: str
    remediation: str = ""
    raw_artifact_path: str = ""
    content_hash: str = ""
    document_retrieved_at: str = ""
    level: int | None = None
    scored: bool | None = None
    # Decidido pela rota que gerou este Finding (docker-exec vs SSH), nunca
    # inferido de nome/heurística -- feeds invariant_api's applicability
    # logic (finding_taxonomy.py) directly: HOST_ONLY_CONTROLS only applies
    # to docker_container, never to a real linux_host. Default preserves
    # every existing caller that predates this field.
    target_type: Literal["linux_host", "docker_container"] = "docker_container"
