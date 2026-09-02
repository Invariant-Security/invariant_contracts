from pydantic import BaseModel


class DiscoveryResult(BaseModel):
    """Resultado da classificação de um único IP feita por
    invariant_discovery -- um IP específico, já expandido de um Endpoint
    que podia ser um CIDR inteiro. `evidence` carrega os sinais brutos
    (portas abertas, banners, headers) que levaram à classificação, pra
    a UI poder mostrar o porquê, não só o resultado.
    """

    ip: str
    classification: str  # "windows"|"linux"|"docker"|"waf"|"firewall"|"vmware"|"unknown"
    confidence: float
    evidence: dict
    scanned_at: str
