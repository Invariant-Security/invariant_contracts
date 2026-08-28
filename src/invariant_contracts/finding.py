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
