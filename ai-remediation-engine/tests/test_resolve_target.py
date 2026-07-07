from job_runner.main import _resolve_target


def test_resolve_target_falco_uses_output_fields(monkeypatch):
    import job_runner.main as m

    monkeypatch.setattr(m.enrichment, "resolve_owning_deployment", lambda ns, pod: "vulnerable-demo")
    payload = {"output_fields": {"k8s.ns.name": "demo", "k8s.pod.name": "vulnerable-demo-abc123"}}
    assert _resolve_target("falco", payload) == ("demo", "vulnerable-demo", "Deployment")


def test_resolve_target_falco_defaults_when_no_pod_name():
    payload = {"output_fields": {"k8s.ns.name": "demo"}}
    assert _resolve_target("falco", payload) == ("demo", "vulnerable-demo", "Deployment")


def test_resolve_target_trivy_uses_resource_labels():
    payload = {
        "metadata": {
            "labels": {
                "trivy-operator.resource.namespace": "demo",
                "trivy-operator.resource.name": "vulnerable-demo",
                "trivy-operator.resource.kind": "Deployment",
            }
        }
    }
    assert _resolve_target("trivy", payload) == ("demo", "vulnerable-demo", "Deployment")


def test_resolve_target_trivy_defaults_when_labels_missing():
    assert _resolve_target("trivy", {"metadata": {}}) == ("demo", "vulnerable-demo", "Deployment")
