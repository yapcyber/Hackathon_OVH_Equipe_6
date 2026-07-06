"""
Enrichissement du contexte avant l'appel IA.

Récupère (lecture seule) le manifeste K8s incriminé, la CVE (Trivy) ou la
règle déclenchée (Falco), et construit un prompt structuré. Le ServiceAccount
utilisé ici n'a que des droits `get`/`list` (voir k8s/job-rbac.yaml) : aucune
écriture sur le cluster n'est possible depuis cette étape.
"""
import json

from kubernetes import client, config


def load_alert(source: str, raw_payload: str) -> dict:
    return {"source": source, "payload": json.loads(raw_payload.replace("'", '"'))}


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
    elif kind.lower() == "pod":
        obj = core_v1.read_namespaced_pod(name, namespace)
    else:
        raise ValueError(f"kind non supporté pour l'enrichissement: {kind}")

    return client.ApiClient().sanitize_for_serialization(obj)


def build_prompt(alert: dict, manifest: dict | None) -> str:
    source = alert["source"]
    payload = alert["payload"]

    if source == "falco":
        finding = (
            f"Règle Falco déclenchée: {payload.get('rule')}\n"
            f"Priorité: {payload.get('priority')}\n"
            f"Détails: {payload.get('output')}\n"
        )
    else:  # trivy
        finding = (
            f"Vulnérabilité(s) Trivy sur l'image {payload.get('image', {}).get('name')}:\n"
            f"{json.dumps(payload.get('vulnerabilities', payload), indent=2)[:4000]}\n"
        )

    manifest_block = (
        f"Manifeste Kubernetes actuel (YAML/JSON):\n{json.dumps(manifest, indent=2)[:6000]}\n"
        if manifest
        else "Manifeste non disponible — se baser uniquement sur l'alerte.\n"
    )

    return f"""Tu es un expert DevSecOps Kubernetes. Voici une alerte de sécurité détectée
en production sur un cluster Managed Kubernetes OVHcloud.

{finding}
{manifest_block}

Propose UNIQUEMENT :
1. Un correctif au format patch YAML (diff minimal, pas de réécriture complète).
2. Une explication courte (3 lignes max) de la cause racine.
3. Si pertinent, une ClusterPolicy Kyverno complémentaire pour prévenir la récidive.

Ne propose jamais une commande à exécuter directement sur le cluster :
le correctif doit uniquement prendre la forme d'un fichier YAML à committer
dans le dépôt GitOps.
"""
