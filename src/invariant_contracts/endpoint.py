from pydantic import BaseModel


class Endpoint(BaseModel):
    """Um IP ou range/CIDR que o cliente pediu pro Invariant olhar. Diferente
    de Target: Target nomeia um container Docker que invariant_assessment já
    alcança via `docker exec` -- Endpoint nomeia um endereço de rede que
    invariant_discovery ainda precisa alcançar e não tem classificação
    nenhuma ainda (pode nem virar um Target no fim -- pode ser um firewall,
    uma VM VMware, etc.).
    """

    address: str  # IP único ("10.0.0.5") ou CIDR ("10.0.0.0/24")
    label: str | None = None
    tags: list[str] = []
