from pydantic import BaseModel


class ProfileLevel(BaseModel):
    """Campos exatos de invariant.normalizer.ProfileLevel."""

    level: int
    applies_to: str


class Control(BaseModel):
    """Campos exatos de invariant.normalizer.Control -- um controle CIS
    normalizado, sem alterar nenhum campo do dataclass original.
    """

    external_id: str
    title: str
    description: str
    scored: bool
    applicability: list[ProfileLevel]
    applicability_tags: list[str]
    rationale: str
    audit: str
    remediation: str
