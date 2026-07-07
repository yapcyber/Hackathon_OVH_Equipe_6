from job_runner import enrichment


def test_load_alert_roundtrip():
    assert enrichment.load_alert("falco", '{"rule": "x"}') == {"source": "falco", "payload": {"rule": "x"}}


def test_build_prompt_falco_includes_rule_and_kind():
    alert = {
        "source": "falco",
        "payload": {"rule": "Terminal shell in container", "priority": "Warning", "output": "..."},
    }
    prompt = enrichment.build_prompt(alert, None, "Deployment")
    assert "Terminal shell in container" in prompt
    assert "Deployment" in prompt


def test_build_prompt_trivy_reads_report_artifact_and_vulnerabilities():
    alert = {
        "source": "trivy",
        "payload": {
            "report": {
                "artifact": {"repository": "nginx", "tag": "latest"},
                "vulnerabilities": [{"vulnerabilityID": "CVE-2024-0001"}],
            }
        },
    }
    prompt = enrichment.build_prompt(alert, None, "Deployment")
    assert "nginx:latest" in prompt
    assert "CVE-2024-0001" in prompt


def test_resolve_owning_deployment_falls_back_to_pod_name_on_error(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("no cluster available in tests")

    monkeypatch.setattr(enrichment.config, "load_incluster_config", boom)
    monkeypatch.setattr(enrichment.config, "load_kube_config", boom)

    assert enrichment.resolve_owning_deployment("demo", "vulnerable-demo-abc123") == "vulnerable-demo-abc123"


def test_build_prompt_includes_business_context_and_asks_for_risk():
    alert = {"source": "trivy", "payload": {"report": {"artifact": {"repository": "checkout", "tag": "1.2.3"}}}}
    business = {
        "last_deploy_days": 30,
        "criticality": "high",
        "freeze_active": True,
        "freeze_until": "2026-12-01",
        "freeze_reason": "Black Friday",
    }
    prompt = enrichment.build_prompt(alert, None, "Deployment", business)
    assert "30 jours" in prompt
    assert "high" in prompt
    assert "2026-12-01" in prompt
    assert "Analyse de risque du déploiement" in prompt


def test_build_prompt_degrades_gracefully_without_business_context():
    alert = {"source": "falco", "payload": {"rule": "x", "priority": "Warning", "output": "..."}}
    # business=None : le prompt doit rester valide et afficher "inconnu"/"unknown"
    prompt = enrichment.build_prompt(alert, None, "Deployment")
    assert "inconnu" in prompt
    assert "unknown" in prompt


def test_days_since_parses_rfc3339_and_handles_garbage():
    from datetime import datetime, timedelta, timezone

    ten_days_ago = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat().replace("+00:00", "Z")
    assert enrichment._days_since(ten_days_ago) == 10
    assert enrichment._days_since(None) is None
    assert enrichment._days_since("pas-une-date") is None


def test_fetch_business_context_never_raises_without_cluster(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("no cluster available in tests")

    monkeypatch.setattr(enrichment.config, "load_incluster_config", boom)
    monkeypatch.setattr(enrichment.config, "load_kube_config", boom)

    ctx = enrichment.fetch_business_context("demo", "checkout", "Deployment")
    assert ctx["criticality"] == "unknown"
    assert ctx["freeze_active"] is False
    assert ctx["last_deploy_days"] is None
