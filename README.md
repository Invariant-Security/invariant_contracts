# invariant_contracts

Modelos Pydantic compartilhados entre os serviços `invariant_*`
(`invariant_ingestion`, `invariant_assessment`, `invariant_api`). Não é um
serviço -- é uma dependência de build-time instalada pelos outros repos.

Parte da separação do monólito `Invariant-Security/Invariant` em
repositórios por domínio de responsabilidade. Ver o plano de refatoração
para o contexto completo.

## Instalar (dos outros repos)

```toml
dependencies = [
    "invariant_contracts @ git+https://github.com/Invariant-Security/invariant_contracts.git@main",
]
```

## Desenvolvimento

```bash
pip install -e ".[dev]"
pytest tests/ -q
```
