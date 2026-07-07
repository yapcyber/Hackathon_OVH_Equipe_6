import time

import webhook_receiver as wr


def test_fingerprint_stable_for_same_falco_rule():
    payload = {"rule": "Terminal shell in container"}
    assert wr._fingerprint("falco", payload) == wr._fingerprint("falco", payload)


def test_fingerprint_differs_by_source():
    payload = {"rule": "same-name"}
    assert wr._fingerprint("falco", payload) != wr._fingerprint("trivy", payload)


def test_fingerprint_trivy_uses_metadata_name():
    a = wr._fingerprint("trivy", {"metadata": {"name": "report-a"}})
    b = wr._fingerprint("trivy", {"metadata": {"name": "report-b"}})
    assert a != b


def test_is_duplicate_flags_immediate_repeat():
    wr._recent_fingerprints.clear()
    assert wr._is_duplicate("abc") is False
    assert wr._is_duplicate("abc") is True


def test_is_duplicate_treats_expired_fingerprint_as_new():
    wr._recent_fingerprints.clear()
    wr._recent_fingerprints["old"] = time.time() - wr.DEDUP_TTL_SECONDS - 1
    assert wr._is_duplicate("old") is False


def test_webhook_auth_disabled_when_no_shared_token(monkeypatch):
    monkeypatch.setattr(wr, "WEBHOOK_SHARED_TOKEN", None)

    class FakeRequest:
        headers: dict = {}

    assert wr._check_webhook_auth(FakeRequest()) is None


def test_webhook_auth_rejects_missing_or_wrong_token(monkeypatch):
    monkeypatch.setattr(wr, "WEBHOOK_SHARED_TOKEN", "expected-token")

    class FakeRequest:
        def __init__(self, headers):
            self.headers = headers

    assert wr._check_webhook_auth(FakeRequest({})).status_code == 401
    assert wr._check_webhook_auth(FakeRequest({"X-Webhook-Token": "wrong"})).status_code == 401
    assert wr._check_webhook_auth(FakeRequest({"X-Webhook-Token": "expected-token"})) is None
