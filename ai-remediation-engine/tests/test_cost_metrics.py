"""
Vérifie que le reporting de tokens depuis un Job alimente bien les compteurs
de tokens ET le compteur de coût en euros exposés sur /metrics.
"""
from fastapi.testclient import TestClient

import webhook_receiver as wr

client = TestClient(wr.app)


def test_job_metrics_endpoint_records_tokens_and_cost():
    # 1 000 000 tokens au prix par défaut de 0,67 €/Mtoken => coût = 0,67 €.
    resp = client.post(
        "/internal/job-metrics",
        json={
            "source": "trivy",
            "outcome": "pr_opened",
            "ai_call_seconds": 2.5,
            "prompt_tokens": 700_000,
            "completion_tokens": 300_000,
        },
    )
    assert resp.status_code == 204

    metrics_text = client.get("/metrics").text
    assert 'ai_remediation_ai_tokens_total{source="trivy",type="prompt"} 700000.0' in metrics_text
    assert 'ai_remediation_ai_tokens_total{source="trivy",type="completion"} 300000.0' in metrics_text
    # 1e6 tokens * 0.67 / 1e6 = 0.67 €
    assert 'ai_remediation_ai_cost_eur_total{source="trivy"} 0.67' in metrics_text


def test_job_metrics_endpoint_tolerates_missing_tokens():
    resp = client.post(
        "/internal/job-metrics",
        json={"source": "falco", "outcome": "ai_error"},
    )
    assert resp.status_code == 204
