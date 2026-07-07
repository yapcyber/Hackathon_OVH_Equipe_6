import httpx
import pytest

from job_runner.pr_generator import KNOWN_REMEDIATION_TARGETS, open_remediation_pr


def test_known_target_mapping_matches_repo_layout():
    assert KNOWN_REMEDIATION_TARGETS[("demo", "vulnerable-demo")] == "apps/vulnerable-demo/deployment.yaml"


def test_unknown_target_raises_before_any_git_or_network_call():
    with pytest.raises(ValueError, match="inconnue"):
        open_remediation_pr(
            alert_source="falco",
            fingerprint="deadbeef",
            namespace="unknown-ns",
            name="unknown-app",
            patch_yaml="kind: Deployment",
            explanation="test",
        )


def test_returns_existing_open_pr_without_touching_git(monkeypatch):
    """Idempotence : si une PR ouverte existe déjà pour ce fingerprint (retry
    K8s), on la renvoie directement sans re-cloner/re-pousser."""
    import job_runner.pr_generator as pr_gen

    def fake_get(url, headers, params, timeout):
        assert params["state"] == "open"
        return httpx.Response(
            200,
            json=[{"html_url": "https://github.com/example/example/pull/42"}],
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(pr_gen.httpx, "get", fake_get)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("ne doit pas cloner/pousser si une PR existe déjà")

    monkeypatch.setattr(pr_gen.subprocess, "run", fail_if_called)

    result = pr_gen.open_remediation_pr(
        alert_source="falco",
        fingerprint="deadbeef",
        namespace="demo",
        name="vulnerable-demo",
        patch_yaml="kind: Deployment",
        explanation="test",
    )
    assert result == "https://github.com/example/example/pull/42"
