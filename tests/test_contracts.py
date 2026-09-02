"""Round-trip check for every contract model: a dict shaped like the real
field names each model documents must validate cleanly, and dumping it
back out must reproduce the same data -- catches a typo'd field name or a
type mismatch against the dataclasses these models mirror.
"""

from invariant_contracts import (
    Control,
    DiscoveryResult,
    Endpoint,
    ExtractedRecommendation,
    Finding,
    ProfileLevel,
    RawArtifact,
    Target,
)


def test_target_round_trip():
    data = {"name": "invariant-debian-baseline"}
    assert Target.model_validate(data).model_dump() == data


def test_endpoint_round_trip_with_defaults():
    data = {"address": "10.0.0.0/24"}
    endpoint = Endpoint.model_validate(data)
    assert endpoint.label is None
    assert endpoint.tags == []

    full = {**data, "label": "escritório", "tags": ["filial-sp"]}
    assert Endpoint.model_validate(full).model_dump() == full


def test_discovery_result_round_trip():
    data = {
        "ip": "10.0.0.5",
        "classification": "linux",
        "confidence": 0.82,
        "evidence": {"open_ports": [22], "banners": {"22": "SSH-2.0-OpenSSH_9.2 Debian"}},
        "scanned_at": "2026-09-02T00:00:00+00:00",
    }
    assert DiscoveryResult.model_validate(data).model_dump() == data


def test_profile_level_round_trip():
    data = {"level": 1, "applies_to": "Server"}
    assert ProfileLevel.model_validate(data).model_dump() == data


def test_control_round_trip():
    data = {
        "external_id": "5.1.20",
        "title": "Ensure sshd PermitRootLogin is disabled",
        "description": "desc",
        "scored": True,
        "applicability": [{"level": 1, "applies_to": "Server"}],
        "applicability_tags": [],
        "rationale": "rationale",
        "audit": "audit",
        "remediation": "remediation",
    }
    control = Control.model_validate(data)
    assert control.model_dump()["external_id"] == data["external_id"]
    assert control.applicability[0].level == 1


def test_finding_round_trip_with_defaults():
    data = {
        "target": "invariant-debian-baseline",
        "external_id": "5.1.20",
        "status": "FAIL",
        "control_title": "Ensure sshd PermitRootLogin is disabled",
        "source_name": "cis",
        "document_name": "debian_linux_11",
        "document_version": "3.0.0",
        "evidence_output": "permitrootlogin yes",
        "collected_at": "2026-08-28T00:00:00+00:00",
    }
    finding = Finding.model_validate(data)
    assert finding.remediation == ""
    assert finding.level is None
    assert finding.scored is None

    full = {**data, "remediation": "fix it", "level": 1, "scored": True}
    assert Finding.model_validate(full).model_dump()["level"] == 1


def test_extracted_recommendation_round_trip():
    data = {
        "external_id": "5.1.20",
        "title": "t",
        "scored": True,
        "profile_applicability": ["Level 1 - Server"],
        "description": "d",
        "rationale": "r",
        "audit": "a",
        "remediation": "m",
    }
    assert ExtractedRecommendation.model_validate(data).model_dump() == data


def test_raw_artifact_round_trip():
    data = {
        "source": "cis",
        "document": "debian_linux_11",
        "version": "3.0.0",
        "content_hash": "abc123",
        "retrieved_at": "2026-08-28T00:00:00+00:00",
        "path": "/app/data/raw/cis_debian_linux_11.pdf",
    }
    assert RawArtifact.model_validate(data).model_dump() == data
