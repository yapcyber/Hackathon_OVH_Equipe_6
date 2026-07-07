"""
Reporting best-effort de métriques depuis le Job éphémère.

Un Job vit quelques secondes à quelques minutes : Prometheus n'a aucune
chance de le scraper directement. Plutôt que de déployer un composant
supplémentaire (Pushgateway), le Job pousse son résultat au webhook receiver
(seul composant durable du moteur, déjà scrapé via ServiceMonitor) sur un
endpoint interne dédié. Un échec de ce reporting ne doit jamais faire
échouer le Job : c'est une métrique, pas une étape du pipeline.
"""
import logging
import os

import httpx

log = logging.getLogger("remediation-job.metrics")

WEBHOOK_METRICS_URL = os.environ.get(
    "WEBHOOK_METRICS_URL",
    "http://ai-remediation-webhook.remediation.svc.cluster.local:8080/internal/job-metrics",
)


def report(source: str, outcome: str, ai_call_seconds: float | None = None) -> None:
    try:
        httpx.post(
            WEBHOOK_METRICS_URL,
            json={"source": source, "outcome": outcome, "ai_call_seconds": ai_call_seconds},
            timeout=5,
        )
    except Exception as exc:
        log.warning("Reporting métriques échoué (non bloquant): %s", exc)
