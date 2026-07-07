"""
Point d'entrée du Job de remédiation (1 exécution = 1 alerte traitée).

Pipeline : enrichissement -> appel AI Endpoints -> parsing -> ouverture PR.
Aucune étape de ce pipeline n'écrit sur le cluster ni ne merge de PR.
"""
import logging
import os
import re
import sys
import time

from job_runner import enrichment, metrics, validation
from job_runner.ai_client import AIEndpointsClient
from job_runner.pr_generator import open_remediation_pr

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("remediation-job")


def _extract_yaml_block(ai_response: str) -> str:
    match = re.search(r"```ya?ml\n(.*?)```", ai_response, re.DOTALL)
    if not match:
        raise ValueError("Aucun bloc YAML trouvé dans la réponse IA — PR non générée.")
    return match.group(1).strip()


def _resolve_target(source: str, payload: dict) -> tuple[str, str, str]:
    """Namespace/name/kind réels de la ressource visée, selon le format propre
    à chaque source d'alerte (Falco: output_fields, Trivy: labels du CR
    VulnerabilityReport)."""
    if source == "falco":
        fields = payload.get("output_fields", {})
        ns = fields.get("k8s.ns.name", "demo")
        pod_name = fields.get("k8s.pod.name", "")
        name = enrichment.resolve_owning_deployment(ns, pod_name) if pod_name else "vulnerable-demo"
        return ns, name, "Deployment"

    # trivy
    labels = payload.get("metadata", {}).get("labels", {})
    ns = labels.get("trivy-operator.resource.namespace", "demo")
    name = labels.get("trivy-operator.resource.name", "vulnerable-demo")
    kind = labels.get("trivy-operator.resource.kind", "Deployment")
    return ns, name, kind


def main() -> int:
    source = os.environ["ALERT_SOURCE"]
    raw_payload = os.environ["ALERT_PAYLOAD"]
    fingerprint = os.environ.get("FINGERPRINT") or os.environ.get("HOSTNAME", "unknown")[-16:]

    alert = enrichment.load_alert(source, raw_payload)
    ns, name, kind = _resolve_target(source, alert["payload"])

    manifest = None
    try:
        manifest = enrichment.fetch_target_manifest(ns, kind, name)
    except Exception as exc:  # lecture best-effort, ne bloque pas le pipeline
        log.warning("Impossible de récupérer le manifeste cible: %s", exc)

    prompt = enrichment.build_prompt(alert, manifest, kind)

    ai_client = AIEndpointsClient()
    started = time.monotonic()
    try:
        ai_response = ai_client.generate_remediation(prompt)
    except Exception:
        metrics.report(source, "ai_error")
        raise
    ai_call_seconds = time.monotonic() - started
    log.info("Réponse IA reçue (%d caractères, %.1fs)", len(ai_response), ai_call_seconds)

    try:
        patch_yaml = _extract_yaml_block(ai_response)
    except ValueError:
        metrics.report(source, "no_yaml_block", ai_call_seconds)
        raise

    try:
        validation.validate_manifest(patch_yaml, kind)
    except validation.ValidationError:
        metrics.report(source, "invalid_yaml", ai_call_seconds)
        raise

    try:
        pr_url = open_remediation_pr(
            alert_source=source,
            fingerprint=fingerprint,
            namespace=ns,
            name=name,
            patch_yaml=patch_yaml,
            explanation=ai_response,
        )
    except Exception:
        metrics.report(source, "pr_error", ai_call_seconds)
        raise

    metrics.report(source, "pr_opened", ai_call_seconds)
    log.info("Pull Request ouverte: %s", pr_url)
    return 0


if __name__ == "__main__":
    sys.exit(main())
