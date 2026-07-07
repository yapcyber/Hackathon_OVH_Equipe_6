"""
Enrichissement du contexte avant l'appel IA.

Récupère (lecture seule) le manifeste K8s incriminé, la CVE (Trivy) ou la
règle déclenchée (Falco), et construit un prompt structuré. Le ServiceAccount
utilisé ici n'a que des droits `get`/`list` (voir k8s/job-rbac.yaml) : aucune
écriture sur le cluster n'est possible depuis cette étape.
"""
import json
import logging
import os
from datetime import datetime, timezone

from kubernetes import client, config

log = logging.getLogger("remediation-job.enrichment")

# Où lire le calendrier de code freeze (ConfigMap simple, lecture seule).
# Sépare volontairement le "quand peut-on déployer" (ops) du "quoi corriger"
# (sécu) : l'équipe plateforme met à jour cette ConfigMap sans toucher au code.
FREEZE_CONFIGMAP_NAMESPACE = os.environ.get("FREEZE_CONFIGMAP_NAMESPACE", "remediation")
FREEZE_CONFIGMAP_NAME = os.environ.get("FREEZE_CONFIGMAP_NAME", "freeze-calendar")

# Label/annotation portant la criticité business d'un workload.
CRITICALITY_KEY = "business-criticality"


def load_alert(source: str, raw_payload: str) -> dict:
    return {"source": source, "payload": json.loads(raw_payload)}


def fetch_target_manifest(namespace: str, kind: str, name: str) -> dict:
    """Lecture seule du manifeste visé par l'alerte, pour donner du contexte à l'IA."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()

    apps_v1 = client.AppsV1Api()
    core_v1 = client.CoreV1Api()

    if kind.lower() == "deployment":
        obj = apps_v1.read_namespaced_deployment(name, namespace)
    elif kind.lower() == "replicaset":
        obj = apps_v1.read_namespaced_replica_set(name, namespace)
    elif kind.lower() == "pod":
        obj = core_v1.read_namespaced_pod(name, namespace)
    else:
        raise ValueError(f"kind non supporté pour l'enrichissement: {kind}")

    return client.ApiClient().sanitize_for_serialization(obj)


def resolve_owning_deployment(namespace: str, pod_name: str) -> str:
    """Falco ne donne que le nom du Pod. Remonte Pod -> ReplicaSet -> Deployment
    (lecture seule, même RBAC que fetch_target_manifest) pour retrouver la
    ressource GitOps réellement gérée dans le dépôt. Retombe sur le nom du Pod
    si la remontée échoue pour N'IMPORTE QUELLE raison (Pod nu non géré par un
    Deployment, config cluster indisponible, RBAC insuffisant, etc.) : cette
    fonction ne doit jamais faire échouer le pipeline, juste dégrader le nom résolu."""
    try:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

        core_v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()

        pod = core_v1.read_namespaced_pod(pod_name, namespace)
        for owner in pod.metadata.owner_references or []:
            if owner.kind == "ReplicaSet":
                rs = apps_v1.read_namespaced_replica_set(owner.name, namespace)
                for rs_owner in rs.metadata.owner_references or []:
                    if rs_owner.kind == "Deployment":
                        return rs_owner.name
    except Exception:
        pass
    return pod_name


def _days_since(rfc3339: str | None) -> int | None:
    if not rfc3339:
        return None
    try:
        dt = datetime.fromisoformat(rfc3339.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return None


def fetch_business_context(namespace: str, name: str, kind: str = "Deployment") -> dict:
    """Contexte OPÉRATIONNEL (pas sécurité) pour permettre à l'IA d'évaluer le
    risque d'APPLIQUER un correctif maintenant : ancienneté du dernier
    déploiement, criticité business déclarée, fenêtre de code freeze active.

    100% lecture seule (deployments + configmaps), best-effort : ne fait JAMAIS
    échouer le pipeline. Un contexte partiel vaut mieux que pas de PR du tout —
    l'IA reçoit alors 'inconnu' pour les champs manquants."""
    ctx: dict = {
        "last_deploy_days": None,
        "criticality": "unknown",
        "freeze_active": False,
        "freeze_until": None,
        "freeze_reason": None,
    }
    try:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

        apps_v1 = client.AppsV1Api()
        core_v1 = client.CoreV1Api()

        if kind.lower() == "deployment":
            dep = apps_v1.read_namespaced_deployment(name, namespace)
            labels = dep.metadata.labels or {}
            annotations = dep.metadata.annotations or {}
            ctx["criticality"] = labels.get(CRITICALITY_KEY) or annotations.get(
                CRITICALITY_KEY, "unknown"
            )
            # Dernier rollout : lastUpdateTime la plus récente parmi les
            # conditions du Deployment, sinon date de création.
            times = [
                c.last_update_time
                for c in (dep.status.conditions or [])
                if c.last_update_time is not None
            ]
            newest = max(times).isoformat() if times else (
                dep.metadata.creation_timestamp.isoformat()
                if dep.metadata.creation_timestamp
                else None
            )
            ctx["last_deploy_days"] = _days_since(newest)

        cm = core_v1.read_namespaced_config_map(FREEZE_CONFIGMAP_NAME, FREEZE_CONFIGMAP_NAMESPACE)
        data = cm.data or {}
        ctx["freeze_active"] = str(data.get("active", "false")).lower() == "true"
        ctx["freeze_until"] = data.get("until")
        ctx["freeze_reason"] = data.get("reason")
    except Exception as exc:
        log.warning("Contexte business partiel (%s) — l'IA recevra 'inconnu'.", exc)
    return ctx


def build_prompt(
    alert: dict,
    manifest: dict | None,
    kind: str = "Deployment",
    business: dict | None = None,
) -> str:
    source = alert["source"]
    payload = alert["payload"]

    if source == "falco":
        finding = (
            f"Règle Falco déclenchée: {payload.get('rule')}\n"
            f"Priorité: {payload.get('priority')}\n"
            f"Détails: {payload.get('output')}\n"
        )
    else:  # trivy: les données utiles sont sous report.* d'un VulnerabilityReport
        report = payload.get("report", {})
        artifact = report.get("artifact", {})
        image = f"{artifact.get('repository', '?')}:{artifact.get('tag', '?')}"
        finding = (
            f"Vulnérabilité(s) Trivy sur l'image {image}:\n"
            f"{json.dumps(report.get('vulnerabilities', report), indent=2)[:4000]}\n"
        )

    manifest_block = (
        f"Manifeste Kubernetes actuel (YAML/JSON):\n{json.dumps(manifest, indent=2)[:6000]}\n"
        if manifest
        else "Manifeste non disponible — se baser uniquement sur l'alerte.\n"
    )

    business = business or {}
    days = business.get("last_deploy_days")
    days_str = f"{days} jours" if days is not None else "inconnu"
    freeze = business.get("freeze_active")
    if freeze:
        freeze_str = (
            f"OUI, code freeze actif jusqu'au {business.get('freeze_until', '?')}"
            f" (raison: {business.get('freeze_reason', 'non précisée')})"
        )
    else:
        freeze_str = "non"
    business_block = (
        "Contexte opérationnel (pour évaluer le risque d'APPLIQUER le correctif, "
        "pas la gravité de la faille) :\n"
        f"- Dernier déploiement de ce workload : il y a {days_str}.\n"
        f"- Criticité business déclarée : {business.get('criticality', 'unknown')}.\n"
        f"- Fenêtre de code freeze active : {freeze_str}.\n"
    )

    return f"""Tu es un expert DevSecOps Kubernetes. Voici une alerte de sécurité détectée
en production sur un cluster Managed Kubernetes OVHcloud.

{finding}
{manifest_block}
{business_block}

Propose UNIQUEMENT, dans cet ordre :
1. Dans le TOUT PREMIER bloc de code ```yaml de ta réponse : le manifeste
   {kind} COMPLET et corrigé (pas un diff partiel). Ce bloc va remplacer
   intégralement le fichier existant dans le dépôt GitOps — il doit donc
   rester un objet Kubernetes valide et complet (apiVersion/kind/metadata/spec),
   pas seulement le fragment corrigé. Fournis TOUJOURS ce correctif, même si
   tu recommandes de ne pas l'appliquer tout de suite : le but est qu'il soit
   prêt, revu et validé — pas forcément appliqué immédiatement.
2. Une explication courte (3 lignes max) de la cause racine, en dehors du bloc YAML.
3. Une section "## Analyse de risque du déploiement" (hors bloc YAML) :
   - un score de risque de l'APPLICATION du correctif (pas de la vulnérabilité) :
     LOW / MEDIUM / HIGH, en croisant la criticité business, l'ancienneté du
     dernier déploiement (un service non redéployé depuis longtemps est plus
     risqué à toucher en urgence) et la fenêtre de code freeze ;
   - une recommandation explicite et datée : appliquer maintenant / reporter à
     la fin du freeze ({business.get('freeze_until') or 'date de fin de freeze'}) /
     appliquer en heures creuses avec rollback préparé.
4. Si pertinent, une ClusterPolicy Kyverno complémentaire pour prévenir la
   récidive, dans un bloc ```yaml SÉPARÉ, placé APRÈS le manifeste corrigé.

Ne propose jamais une commande à exécuter directement sur le cluster :
le correctif doit uniquement prendre la forme d'un fichier YAML à committer
dans le dépôt GitOps.
"""
