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
    "invariant_contracts @ git+https://github.com/Invariant-Security/invariant_contracts.git@v0.2.0",
]
```

Sempre fixe uma **tag** (`@vX.Y.Z`), nunca `@main`: o build de cada serviço
precisa ser reproduzível e uma mudança aqui não pode chegar sem querer.

## Contratos públicos (`invariant_contracts.v1`)

O pacote `v1` é contrato **externo** — API `/v1` do cliente vendedor,
protocolo appliance ↔ central de licenças e evento de webhook. Os modelos da
raiz (`Finding`, `Endpoint`...) são internos e podem mudar com o console.

Política de compatibilidade: ver `invariant_contracts.v1.POLICY` (só
mudanças aditivas; remover/renomear = `/v2`; depreciação ≥ 6 meses).

O teste `tests/test_v1_contracts.py::test_schema_snapshot_is_unchanged`
compara o JSON Schema atual com `tests/snapshots/v1.json`. Se ele falhar, o
contrato mudou: só regere o snapshot se a mudança for intencional e aditiva.

Funções puras compartilhadas:
- `invariant_contracts.usage`: normalização de IP e de container (identidade
  comercial), período UTC e hash de uso enviado à central.
- `invariant_contracts.signing`: assinatura/verificação do webhook (HMAC) e
  envelope do certificado de licença.

## Desenvolvimento

```bash
pip install -e ".[dev]"
pytest tests/ -q
```
