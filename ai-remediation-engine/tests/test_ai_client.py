import httpx
import pytest

from job_runner.ai_client import AIEndpointsClient


def test_succeeds_immediately_on_200():
    def handler(request):
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    ai = AIEndpointsClient(token="t")
    result = ai.generate_remediation("prompt", transport=httpx.MockTransport(handler))
    assert result.content == "ok"


def test_parses_token_usage_from_response():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 1200, "completion_tokens": 340},
            },
        )

    ai = AIEndpointsClient(token="t")
    result = ai.generate_remediation("prompt", transport=httpx.MockTransport(handler))
    assert result.prompt_tokens == 1200
    assert result.completion_tokens == 340


def test_missing_usage_block_defaults_to_zero_tokens():
    def handler(request):
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    ai = AIEndpointsClient(token="t")
    result = ai.generate_remediation("prompt", transport=httpx.MockTransport(handler))
    assert result.prompt_tokens == 0
    assert result.completion_tokens == 0


def test_retries_on_500_then_succeeds():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] < 2:
            return httpx.Response(500, json={"error": "boom"})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    ai = AIEndpointsClient(token="t")
    result = ai.generate_remediation(
        "prompt", transport=httpx.MockTransport(handler), max_retries=3, backoff_seconds=0
    )
    assert result.content == "ok"
    assert calls["n"] == 2


def test_retries_on_429():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] < 2:
            return httpx.Response(429)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    ai = AIEndpointsClient(token="t")
    result = ai.generate_remediation(
        "prompt", transport=httpx.MockTransport(handler), max_retries=3, backoff_seconds=0
    )
    assert result.content == "ok"
    assert calls["n"] == 2


def test_gives_up_after_max_retries():
    def handler(request):
        return httpx.Response(503)

    ai = AIEndpointsClient(token="t")
    with pytest.raises(httpx.HTTPStatusError):
        ai.generate_remediation(
            "prompt", transport=httpx.MockTransport(handler), max_retries=2, backoff_seconds=0
        )


def test_does_not_retry_on_4xx_client_errors():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(400)

    ai = AIEndpointsClient(token="t")
    with pytest.raises(httpx.HTTPStatusError):
        ai.generate_remediation(
            "prompt", transport=httpx.MockTransport(handler), max_retries=3, backoff_seconds=0
        )
    assert calls["n"] == 1
