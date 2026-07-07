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
