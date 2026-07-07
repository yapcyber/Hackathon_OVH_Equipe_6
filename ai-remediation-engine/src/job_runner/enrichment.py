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


def build_prompt(alert: dict, manifest: dict | None, kind: str = "Deployment") -> str:
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

    return f"""Tu es un expert DevSecOps Kubernetes. Voici une alerte de sécurité détectée
en production sur un cluster Managed Kubernetes OVHcloud.

{finding}
{manifest_block}

Propose UNIQUEMENT, dans cet ordre :
1. Dans le TOUT PREMIER bloc de code ```yaml de ta réponse : le manifeste
   {kind} COMPLET et corrigé (pas un diff partiel). Ce bloc va remplacer
   intégralement le fichier existant dans le dépôt GitOps — il doit donc
   rester un objet Kubernetes valide et complet (apiVersion/kind/metadata/spec),
   pas seulement le fragment corrigé.
2. Une explication courte (3 lignes max) de la cause racine, en dehors du bloc YAML.
3. Si pertinent, une ClusterPolicy Kyverno complémentaire pour prévenir la
   récidive, dans un bloc ```yaml SÉPARÉ, placé APRÈS le manifeste corrigé.

Ne propose jamais une commande à exécuter directement sur le cluster :
le correctif doit uniquement prendre la forme d'un fichier YAML à committer
dans le dépôt GitOps.
"""
