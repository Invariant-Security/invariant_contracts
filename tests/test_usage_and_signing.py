"""Funções puras de identidade de uso e de assinatura (testes unitários)."""

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from invariant_contracts.signing import (
    canonical_json,
    encode_certificate,
    sign_webhook,
    split_certificate,
    verify_webhook,
)
from invariant_contracts.usage import (
    normalize_container_identity,
    normalize_host_ip,
    period_bounds,
    usage_host_hash,
    usage_period,
)


# ---------- IP ----------
@pytest.mark.parametrize(
    "a,b",
    [
        ("2001:db8:0:0:0:0:0:1", "2001:DB8::1"),
        ("2001:0db8::0001", "2001:db8::1"),
        ("::ffff:10.0.0.5", "10.0.0.5"),
        (" 10.0.0.5 ", "10.0.0.5"),
    ],
)
def test_equivalent_ips_normalize_to_the_same_identity(a, b):
    assert normalize_host_ip(a) == normalize_host_ip(b)


def test_distinct_ips_stay_distinct():
    assert normalize_host_ip("10.0.0.5") != normalize_host_ip("10.0.0.6")


@pytest.mark.parametrize("bad", ["10.0.0.0/24", "host.local", "", "999.1.1.1"])
def test_non_ip_is_rejected(bad):
    with pytest.raises(ValueError):
        normalize_host_ip(bad)


# ---------- container ----------
def _compose(project="Loja", service="Web", number="1"):
    return {
        "com.docker.compose.project": project,
        "com.docker.compose.service": service,
        "com.docker.compose.container-number": number,
    }


def test_recreated_compose_container_keeps_identity():
    first = normalize_container_identity("loja-web-1", _compose())
    recreated = normalize_container_identity("/loja_web_1_abc123", _compose())
    assert first == recreated == "compose:loja/web/1"


def test_compose_replicas_are_distinct():
    assert normalize_container_identity("x", _compose(number="1")) != normalize_container_identity(
        "x", _compose(number="2")
    )


def test_non_compose_container_falls_back_to_normalized_name():
    assert normalize_container_identity("/Meu Container") == "name:meu-container"
    assert normalize_container_identity("meu-container") == "name:meu-container"


def test_empty_container_name_is_rejected():
    with pytest.raises(ValueError):
        normalize_container_identity("///")


# ---------- período UTC ----------
def test_period_is_utc_even_for_a_brazil_local_time():
    # 30/09 22:00 em São Paulo = 01/10 01:00 UTC -> outubro
    local = datetime(2026, 9, 30, 22, 0, tzinfo=ZoneInfo("America/Sao_Paulo"))
    assert usage_period(local) == "2026-10"


def test_month_boundary_to_the_microsecond():
    end_sept = datetime(2026, 9, 30, 23, 59, 59, 999999, tzinfo=timezone.utc)
    assert usage_period(end_sept) == "2026-09"
    assert usage_period(end_sept + timedelta(microseconds=1)) == "2026-10"


def test_naive_datetime_is_rejected():
    with pytest.raises(ValueError):
        usage_period(datetime(2026, 10, 1))


def test_period_bounds_wrap_the_year():
    start, end = period_bounds("2026-12")
    assert start == datetime(2026, 12, 1, tzinfo=timezone.utc)
    assert end == datetime(2027, 1, 1, tzinfo=timezone.utc)


# ---------- hash de uso ----------
def test_usage_hash_is_stable_and_separates_kind_and_key():
    key = b"k" * 32
    h = usage_host_hash(key, "linux_host", "10.0.0.5")
    assert h == usage_host_hash(key, "linux_host", "10.0.0.5")
    assert len(h) == 64
    assert h != usage_host_hash(key, "docker_container", "10.0.0.5")
    assert h != usage_host_hash(key, "linux_host", "10.0.0.6")
    assert h != usage_host_hash(b"x" * 32, "linux_host", "10.0.0.5")


def test_usage_hash_rejects_bad_input():
    with pytest.raises(ValueError):
        usage_host_hash(b"", "linux_host", "10.0.0.5")
    with pytest.raises(ValueError):
        usage_host_hash(b"k", "server", "10.0.0.5")


# ---------- webhook ----------
def test_webhook_signature_round_trip_and_tamper_detection():
    body = b'{"id":"1"}'
    header = sign_webhook("segredo", body, timestamp=1_000)
    assert verify_webhook("segredo", body, header, now=1_010)
    assert not verify_webhook("segredo", b'{"id":"2"}', header, now=1_010)
    assert not verify_webhook("outro", body, header, now=1_010)


def test_webhook_signature_rejects_old_or_malformed():
    body = b"{}"
    header = sign_webhook("s", body, timestamp=1_000)
    assert not verify_webhook("s", body, header, now=1_000 + 301)
    for bad in ("", "t=abc,v1=00", "v1=00", "garbage"):
        assert not verify_webhook("s", body, bad, now=1_000)


# ---------- certificado ----------
def test_canonical_json_is_order_independent():
    assert canonical_json({"b": 1, "a": "ç"}) == canonical_json({"a": "ç", "b": 1}) == '{"a":"ç","b":1}'.encode()


def test_certificate_envelope_round_trip():
    payload, sig = canonical_json({"x": 1}), b"\x00\xff" * 32
    token = encode_certificate(payload, sig)
    assert "=" not in token and token.count(".") == 1
    assert split_certificate(token) == (payload, sig)
