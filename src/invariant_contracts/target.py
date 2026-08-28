from pydantic import BaseModel


class Target(BaseModel):
    """Identifica um alvo avaliável. Hoje é exatamente o `target: str` que
    invariant.assessment.assess_target()/facts.collect_facts() já recebem
    (o nome do container Docker) -- o monólito não tem nenhum conceito mais
    rico de "Target" ainda (sem IP/credenciais/tags), então este contrato
    não inventa um.
    """

    name: str
