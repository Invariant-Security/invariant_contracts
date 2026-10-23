"""Assinatura de webhook (testes unitários)."""

from invariant_contracts.signing import sign_webhook, verify_webhook


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
