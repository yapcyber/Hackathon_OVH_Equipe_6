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


def main() -> int:
    source = os.environ["ALERT_SOURCE"]
    raw_payload = os.environ["ALERT_PAYLOAD"]
    fingerprint = os.environ.get("HOSTNAME", "unknown")[-16:]

    alert = enrichment.load_alert(source, raw_payload)

    manifest = None
    try:
        ns = alert["payload"].get("namespace", "demo")
        name = alert["payload"].get("name", "vulnerable-demo")
        manifest = enrichment.fetch_target_manifest(ns, "Deployment", name)
    except Exception as exc:  # lecture best-effort, ne bloque pas le pipeline
        log.warning("Impossible de récupérer le manifeste cible: %s", exc)

    prompt = enrichment.build_prompt(alert, manifest)

    client = AIEndpointsClient()
    ai_response = client.generate_remediation(prompt)
    log.info("Réponse IA reçue (%d caractères)", len(ai_response))

    patch_yaml = _extract_yaml_block(ai_response)

    pr_url = open_remediation_pr(
        alert_source=source,
        fingerprint=fingerprint,
        patch_yaml=patch_yaml,
        explanation=ai_response,
    )
    log.info("Pull Request ouverte: %s", pr_url)
    return 0


if __name__ == "__main__":
    sys.exit(main())
