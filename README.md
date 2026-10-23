# invariant_contracts

Shared [Pydantic](https://docs.pydantic.dev/) data contracts for
[Invariant](https://invariantsec.org), an open-source CIS compliance
assessment toolkit for Linux hosts and containers.

This package is the common vocabulary of the Invariant components: the
assessment engine, the CIS benchmark ingestion pipeline and network
discovery all exchange these models. It is a library, not a service.

## Install

```toml
dependencies = [
    "invariant_contracts @ git+https://github.com/Invariant-Security/invariant_contracts.git@v0.2.0",
]
```

Always pin a **tag** (`@vX.Y.Z`), never a branch, so builds stay
reproducible.

## Versioned contracts (`invariant_contracts.v1`)

`v1` holds the external, versioned contracts. Compatibility policy (see
`invariant_contracts.v1.POLICY`):

- only additive changes within `v1`;
- removing or renaming a field means a new `v2`;
- deprecations last at least 6 months.

`tests/test_v1_contracts.py::test_schema_snapshot_is_unchanged` compares the
current JSON Schema with `tests/snapshots/v1.json`. If it fails, the contract
changed: regenerate the snapshot only when the change is intentional and
additive.

Models at the package root (`Finding`, `Endpoint`, ...) are internal and may
change between releases.

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -q
```

## Contributing

Contributions are welcome under the DCO, with no CLA. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE).
