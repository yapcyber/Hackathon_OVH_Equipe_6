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

import yaml

from job_runner import enrichment, metrics, validation
from job_runner.ai_client import AIEndpointsClient
from job_runner.pr_generator import open_remediation_pr

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("remediation-job")

# Tolérant sur l'étiquette de langage (```yaml, ```yml, ```YAML, ou même nue
# ``` sans étiquette) : certains modèles varient la casse ou l'omettent.
_FENCE_RE = re.compile(r"```(?:ya?ml)?[ \t]*\n(.*?)```", re.DOTALL | re.IGNORECASE)


def _extract_yaml_block(ai_response: str) -> str:
    """Prend le premier bloc de code qui parse comme un manifeste Kubernetes
    valide (dict avec une clé 'kind'), pas juste le tout premier bloc de code
    de la réponse — l'IA peut placer une note ou un extrait non-YAML avant."""
    for candidate in _FENCE_RE.findall(ai_response):
        text = candidate.strip()
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if isinstance(parsed, dict) and "kind" in parsed:
            return text
    raise ValueError(
        "Aucun bloc de code contenant un manifeste Kubernetes valide (avec 'kind') "
        "trouvé dans la réponse IA — PR non générée."
    )


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

    # Contexte opérationnel pour l'analyse de risque business (best-effort,
    # ne lève jamais — voir fetch_business_context).
    business = enrichment.fetch_business_context(ns, name, kind)
    log.info(
        "Contexte business: criticité=%s, dernier déploiement=%s j, freeze=%s",
        business.get("criticality"), business.get("last_deploy_days"), business.get("freeze_active"),
    )

    prompt = enrichment.build_prompt(alert, manifest, kind, business)

    ai_client = AIEndpointsClient()
    started = time.monotonic()
    try:
        ai = ai_client.generate_remediation(prompt)
    except Exception:
        metrics.report(source, "ai_error")
        raise
    ai_call_seconds = time.monotonic() - started
    # Tokens rapportés sur TOUTES les issues post-appel : le coût est engagé
    # dès que l'IA a répondu, même si on n'ouvre finalement pas de PR.
    toks = {"prompt_tokens": ai.prompt_tokens, "completion_tokens": ai.completion_tokens}
    log.info(
        "Réponse IA reçue (%d car., %.1fs, %d+%d tokens)",
        len(ai.content), ai_call_seconds, ai.prompt_tokens, ai.completion_tokens,
    )

    try:
        patch_yaml = _extract_yaml_block(ai.content)
    except ValueError:
        metrics.report(source, "no_yaml_block", ai_call_seconds, **toks)
        raise

    try:
        validation.validate_manifest(patch_yaml, kind)
    except validation.ValidationError:
        metrics.report(source, "invalid_yaml", ai_call_seconds, **toks)
        raise

    try:
        pr_url = open_remediation_pr(
            alert_source=source,
            fingerprint=fingerprint,
            namespace=ns,
            name=name,
            patch_yaml=patch_yaml,
            explanation=ai.content,
        )
    except Exception:
        metrics.report(source, "pr_error", ai_call_seconds, **toks)
        raise

    metrics.report(source, "pr_opened", ai_call_seconds, **toks)
    log.info("Pull Request ouverte: %s", pr_url)
    return 0


if __name__ == "__main__":
    sys.exit(main())
