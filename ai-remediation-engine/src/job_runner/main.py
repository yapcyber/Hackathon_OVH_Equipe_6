"""
Point d'entrée du Job de remédiation (1 exécution = 1 alerte traitée).

Pipeline : enrichissement -> appel AI Endpoints -> parsing -> ouverture PR.
Aucune étape de ce pipeline n'écrit sur le cluster ni ne merge de PR.
"""
import logging
import os
import re
import sys

from job_runner import enrichment
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

    client = AIEndpointsClient()
    ai_response = client.generate_remediation(prompt)
    log.info("Réponse IA reçue (%d caractères)", len(ai_response))

    patch_yaml = _extract_yaml_block(ai_response)

    pr_url = open_remediation_pr(
        alert_source=source,
        fingerprint=fingerprint,
        namespace=ns,
        name=name,
        patch_yaml=patch_yaml,
        explanation=ai_response,
    )
    log.info("Pull Request ouverte: %s", pr_url)
    return 0


if __name__ == "__main__":
    sys.exit(main())
