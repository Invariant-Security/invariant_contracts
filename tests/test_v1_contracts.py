"""Contratos públicos v1: snapshot congelado + regras de validação."""

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from invariant_contracts import v1
from invariant_contracts.v1.schema_export import export

FP = "SHA256:" + "A" * 43  # valor obviamente falso, formato OpenSSH
PW = {"host_key_type": "ssh-ed25519", "host_key_fingerprint": FP}

SNAPSHOT = Path(__file__).parent / "snapshots" / "v1.json"


def test_schema_snapshot_is_unchanged():
    current = json.loads(json.dumps(export(), sort_keys=True))
    frozen = json.loads(SNAPSHOT.read_text())
    assert current == frozen, (
        "O contrato v1 mudou. Se a mudança for intencional E aditiva (ver v1.POLICY), "
        "regere: python -m invariant_contracts.v1.schema_export > tests/snapshots/v1.json"
    )


def test_every_error_code_value_is_stable():
    assert {c.value for c in v1.ErrorCode} >= {
        "unauthorized",
        "forbidden_scope",
        "not_found",
        "validation_error",
        "rate_limited",
        "idempotency_mismatch",
        "idempotency_in_progress",
        "license_required",
        "license_expired",
        "license_revoked",
        "findings_not_stored",
        "host_key_mismatch",
    }


@pytest.mark.parametrize("model", [v1.TargetCreate, v1.Summary, v1.ErrorBody])
def test_unknown_fields_are_rejected(model):
    base = {
        v1.TargetCreate: {"address": "10.0.0.5"},
        v1.Summary: {"passed": 1, "failed": 0, "not_assessed": 0, "not_applicable": 0, "compliance_pct": 100},
        v1.ErrorBody: {"code": "not_found", "message": "x", "request_id": "r"},
    }[model]
    model.model_validate(base)
    with pytest.raises(ValidationError):
        model.model_validate({**base, "campo_desconhecido": 1})


def test_ssh_credentials_require_exactly_the_matching_secret():
    v1.SSHCredentials(username="u", auth_method="password", password="p", **PW)
    v1.SSHCredentials(username="u", auth_method="key", private_key="-----BEGIN")
    for bad in (
        {"auth_method": "password", **PW},
        {"auth_method": "key"},
        {"auth_method": "password", "password": "p", "private_key": "k", **PW},
        {"auth_method": "key", "private_key": "k", "password": "p"},
        {"auth_method": "token", "password": "p"},
    ):
        with pytest.raises(ValidationError):
            v1.SSHCredentials(username="u", **bad)


def test_ssh_secrets_never_appear_in_repr():
    creds = v1.SSHCredentials(username="u", auth_method="password", password="s3gr3d0", **PW)
    assert "s3gr3d0" not in repr(creds)


def test_assessment_request_ip_must_be_an_ip():
    ssh = {"username": "u", "auth_method": "password", "password": "p", **PW}
    assert str(v1.AssessmentRequest(ssh=ssh, ip="10.0.0.5").ip) == "10.0.0.5"
    with pytest.raises(ValidationError):
        v1.AssessmentRequest(ssh=ssh, ip="10.0.0.0/24")


def test_summary_bounds():
    with pytest.raises(ValidationError):
        v1.Summary(passed=-1, failed=0, not_assessed=0, not_applicable=0, compliance_pct=None)
    with pytest.raises(ValidationError):
        v1.Summary(passed=1, failed=0, not_assessed=0, not_applicable=0, compliance_pct=101)


SUMMARY = {"passed": 1, "failed": 1, "not_assessed": 0, "not_applicable": 0, "compliance_pct": 50}


def _event(target):
    return {
        "event_id": str(uuid4()),
        "event_type": "assessment.completed",
        "schema_version": 1,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "installation_id": str(uuid4()),
        "assessment_id": str(uuid4()),
        "data": {"source": "api", "summary": SUMMARY, "target": target},
    }


def test_webhook_target_is_discriminated_by_kind():
    host = v1.WebhookEvent.model_validate(
        _event({"kind": "linux_host", "target_id": 1, "address": "10.0.0.0/24", "assessed_ip": "10.0.0.5"})
    )
    assert isinstance(host.data.target, v1.HostRef)
    ctr = v1.WebhookEvent.model_validate(_event({"kind": "docker_container", "name": "compose:app/web/1"}))
    assert isinstance(ctr.data.target, v1.ContainerRef)


def test_webhook_event_requires_identity_fields():
    good = _event({"kind": "docker_container", "name": "name:x"})
    assert v1.WebhookEvent.model_validate(good).schema_version == 1
    for field in ("event_id", "event_type", "occurred_at", "assessment_id", "installation_id"):
        broken = {k: v for k, v in good.items() if k != field}
        with pytest.raises(ValidationError):
            v1.WebhookEvent.model_validate(broken)
    with pytest.raises(ValidationError):
        v1.WebhookEvent.model_validate({**good, "schema_version": 2})


def _envelope(**over):
    base = {
        "assessment_id": str(uuid4()),
        "target_id": 1,
        "assessed_ip": "10.0.0.5",
        "assessed_at": datetime.now(timezone.utc).isoformat(),
        "source": "api",
        "summary": SUMMARY,
        "findings": [],
        "findings_omitted_reason": None,
    }
    return {**base, **over}


def test_findings_and_omitted_reason_are_mutually_exclusive():
    v1.AssessmentEnvelope.model_validate(_envelope())
    v1.AssessmentEnvelope.model_validate(_envelope(findings=None, findings_omitted_reason="not_stored"))
    for bad in (
        _envelope(findings=None, findings_omitted_reason=None),
        _envelope(findings=[], findings_omitted_reason="not_stored"),
        _envelope(findings=None, findings_omitted_reason="whatever"),
    ):
        with pytest.raises(ValidationError):
            v1.AssessmentEnvelope.model_validate(bad)


def test_assessment_has_no_inline_pdf():
    ssh = {"username": "u", "auth_method": "password", "password": "p", **PW}
    with pytest.raises(ValidationError):
        v1.AssessmentRequest(ssh=ssh, report="technical")
    with pytest.raises(ValidationError):
        v1.AssessmentEnvelope.model_validate(_envelope(report={"kind": "technical"}))


def test_ssh_credentials_are_input_only():
    creds = v1.SSHCredentials(username="u", auth_method="password", password="s3gr3d0", **PW)
    dumped = creds.model_dump_json()
    assert "s3gr3d0" not in dumped and "password" not in creds.model_dump()
    key = v1.SSHCredentials(username="u", auth_method="key", private_key="-----BEGIN KEY")
    assert "BEGIN" not in key.model_dump_json()
    schema = v1.SSHCredentials.model_json_schema()
    assert schema.get("writeOnly") is True
    assert schema["properties"]["password"]["writeOnly"] is True
    assert schema["properties"]["private_key"]["writeOnly"] is True


@pytest.mark.parametrize(
    "model",
    [v1.Target, v1.DiscoveryHost, v1.AssessmentEnvelope, v1.AssessmentListItem, v1.ErrorResponse,
     v1.WebhookEvent],
)
def test_no_output_model_can_carry_credentials(model):
    text = json.dumps(model.model_json_schema()).lower()
    for forbidden in ("sshcredentials", "password", "private_key", "license_key"):
        assert forbidden not in text, f"{model.__name__} expõe {forbidden}"


def _ssh(**over):
    return {"username": "u", "auth_method": "key", "private_key": "k", **over}


def test_host_key_fields_are_optional_for_key_auth():
    c = v1.SSHCredentials(**_ssh())
    assert c.host_key_type is None and c.host_key_fingerprint is None and c.host_key_mode is None


def test_host_key_valid_combinations():
    v1.SSHCredentials(**_ssh(host_key_mode="first_use"))
    v1.SSHCredentials(**_ssh(host_key_mode="pinned", **PW))
    v1.SSHCredentials(**_ssh(**PW))
    v1.SSHCredentials(username="u", auth_method="password", password="p", host_key_mode="pinned", **PW)
    for t in ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"):
        v1.SSHCredentials(**_ssh(host_key_type=t, host_key_fingerprint=FP))


@pytest.mark.parametrize(
    "bad",
    [
        {"host_key_mode": "pinned"},
        {"host_key_mode": "pinned", "host_key_type": "ssh-ed25519"},
        {"host_key_mode": "first_use", **PW},
        {"host_key_type": "ssh-ed25519"},
        {"host_key_fingerprint": FP},
        {"host_key_mode": "other"},
        {"host_key_type": "ssh-dss", "host_key_fingerprint": FP},
        {"host_key_type": "ssh-ed25519", "host_key_fingerprint": "SHA256:curto"},
        {"host_key_type": "ssh-ed25519", "host_key_fingerprint": "MD5:" + "A" * 43},
        {"host_key_type": "ssh-ed25519", "host_key_fingerprint": FP + "="},
    ],
)
def test_host_key_invalid_combinations(bad):
    with pytest.raises(ValidationError):
        v1.SSHCredentials(**_ssh(**bad))


@pytest.mark.parametrize("extra", [{}, {"host_key_mode": "first_use"}])
def test_password_requires_fingerprint(extra):
    with pytest.raises(ValidationError):
        v1.SSHCredentials(username="u", auth_method="password", password="p", **extra)


def test_envelope_host_key_result_fields():
    old = v1.AssessmentEnvelope.model_validate(_envelope())
    assert old.host_key_observed is None and old.host_key_verification is None
    new = v1.AssessmentEnvelope.model_validate(
        _envelope(host_key_observed={"type": "ssh-ed25519", "fingerprint": FP}, host_key_verification="retrust")
    )
    assert new.host_key_observed.fingerprint == FP
    for bad in ({"host_key_verification": "x"}, {"host_key_observed": {"type": "ssh-ed25519", "fingerprint": "x"}}):
        with pytest.raises(ValidationError):
            v1.AssessmentEnvelope.model_validate(_envelope(**bad))
