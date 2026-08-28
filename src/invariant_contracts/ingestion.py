from pydantic import BaseModel


class ExtractedRecommendation(BaseModel):
    """Campos exatos de invariant.extractor.ExtractedRecommendation."""

    external_id: str
    title: str
    scored: bool
    profile_applicability: list[str]
    description: str
    rationale: str
    audit: str
    remediation: str


class RawArtifact(BaseModel):
    """Campos exatos de invariant.collector.RawArtifact. Contrato
    compartilhado (não só interno a invariant_ingestion) porque
    invariant_api persiste um document_version a partir desta forma depois
    de chamar POST /ingestion/fetch -- é um limite real de repositório.
    """

    source: str
    document: str
    version: str
    content_hash: str
    retrieved_at: str
    path: str
