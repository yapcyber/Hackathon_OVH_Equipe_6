"""
Webhook Receiver — point d'entrée unique pour Falcosidekick et Trivy Operator.

Rôle strictement limité à :
  1. valider/normaliser le payload entrant,
  2. dédoublonner (évite un Job par alerte identique répétée),
  3. créer un Kubernetes Job éphémère qui fera le vrai travail (enrichissement,
     appel IA, génération de PR).

Ce composant ne possède AUCUN droit d'écriture sur le cluster au-delà de
`create` sur des Jobs dans son propre namespace (voir k8s/webhook-rbac.yaml).
Il ne détient jamais le token AI Endpoints ni le token Git.
"""
import hashlib
import json
import logging
import os
import time

from fastapi import FastAPI, Request, Response
from kubernetes import client, config

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("webhook-receiver")

NAMESPACE = os.environ.get("NAMESPACE", "remediation")
JOB_IMAGE = os.environ["JOB_IMAGE"]  # image de ai-remediation-engine/Dockerfile
DEDUP_TTL_SECONDS = int(os.environ.get("DEDUP_TTL_SECONDS", "300"))

# Namespaces scannés/observés par notre propre stack de sécurité : on ignore
# systématiquement leurs alertes pour éviter les boucles auto-référentielles
# (Trivy qui scanne les Jobs de remédiation, Falco qui flag le webhook lui-même).
WATCHED_NAMESPACE = os.environ.get("WATCHED_NAMESPACE", "demo")
IGNORED_NAMESPACES = {"remediation", "kube-system", "argocd", "kyverno", "trivy-system", "monitoring", "falco"}

app = FastAPI()
_recent_fingerprints: dict[str, float] = {}

try:
    config.load_incluster_config()
except config.ConfigException:
    config.load_kube_config()

batch_v1 = client.BatchV1Api()


def _fingerprint(source: str, payload: dict) -> str:
    if source == "falco":
        identity = payload.get("rule", "")
    else:  # trivy: une VulnerabilityReport est identifiée par son nom (= image scannée)
        identity = payload.get("metadata", {}).get("name", "")
    key = f"{source}:{identity}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _is_duplicate(fp: str) -> bool:
    now = time.time()
    # purge best-effort
    for k in [k for k, t in _recent_fingerprints.items() if now - t > DEDUP_TTL_SECONDS]:
        _recent_fingerprints.pop(k, None)
    if fp in _recent_fingerprints:
        return True
    _recent_fingerprints[fp] = now
    return False


def _create_remediation_job(source: str, fp: str, payload: dict) -> str:
    job_name = f"remediate-{source}-{fp}-{int(time.time())}"
    job = client.V1Job(
        metadata=client.V1ObjectMeta(
            name=job_name,
            namespace=NAMESPACE,
            labels={"app": "ai-remediation-engine", "source": source},
        ),
        spec=client.V1JobSpec(
            backoff_limit=2,
            ttl_seconds_after_finished=3600,
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": "ai-remediation-job"}),
                spec=client.V1PodSpec(
                    service_account_name="ai-remediation-job",
                    restart_policy="Never",
                    containers=[
                        client.V1Container(
                            name="remediate",
                            image=JOB_IMAGE,
                            command=["python", "-m", "job_runner.main"],
                            env=[
                                client.V1EnvVar(name="ALERT_SOURCE", value=source),
                                client.V1EnvVar(name="ALERT_PAYLOAD", value=json.dumps(payload)),
                                client.V1EnvVar(name="FINGERPRINT", value=fp),
                                client.V1EnvVar(
                                    name="OVH_AI_ENDPOINTS_ACCESS_TOKEN",
                                    value_from=client.V1EnvVarSource(
                                        secret_key_ref=client.V1SecretKeySelector(
                                            name="ai-endpoints-credentials", key="token"
                                        )
                                    ),
                                ),
                                client.V1EnvVar(
                                    name="GIT_PR_TOKEN",
                                    value_from=client.V1EnvVarSource(
                                        secret_key_ref=client.V1SecretKeySelector(
                                            name="git-pr-credentials", key="token"
                                        )
                                    ),
                                ),
                                client.V1EnvVar(
                                    name="GITOPS_REPO_URL",
                                    value="https://github.com/yapcyber/Hackathon_OVH_Equipe_6.git",
                                ),
                                client.V1EnvVar(
                                    name="GITHUB_REPO_SLUG",
                                    value="yapcyber/Hackathon_OVH_Equipe_6",
                                ),
                            ],
                            resources=client.V1ResourceRequirements(
                                requests={"cpu": "100m", "memory": "128Mi"},
                                limits={"cpu": "500m", "memory": "256Mi"},
                            ),
                        )
                    ],
                ),
            ),
        ),
    )
    batch_v1.create_namespaced_job(namespace=NAMESPACE, body=job)
    return job_name


@app.post("/webhook/falco")
async def falco_webhook(request: Request):
    payload = await request.json()
    ns = payload.get("output_fields", {}).get("k8s.ns.name")
    if ns in IGNORED_NAMESPACES or ns != WATCHED_NAMESPACE:
        return Response(status_code=202, content=f"namespace '{ns}' hors périmètre, ignoré")
    fp = _fingerprint("falco", payload)
    if _is_duplicate(fp):
        return Response(status_code=202, content="duplicate, ignored")
    job_name = _create_remediation_job("falco", fp, payload)
    log.info("Job créé depuis alerte Falco: %s", job_name)
    return {"job": job_name}


@app.post("/webhook/trivy")
async def trivy_webhook(request: Request):
    payload = await request.json()
    if payload.get("kind") != "VulnerabilityReport":
        return Response(status_code=202, content="rapport non-VulnerabilityReport, ignoré")
    ns = payload.get("metadata", {}).get("namespace")
    if ns in IGNORED_NAMESPACES or ns != WATCHED_NAMESPACE:
        return Response(status_code=202, content=f"namespace '{ns}' hors périmètre, ignoré")
    fp = _fingerprint("trivy", payload)
    if _is_duplicate(fp):
        return Response(status_code=202, content="duplicate, ignored")
    job_name = _create_remediation_job("trivy", fp, payload)
    log.info("Job créé depuis rapport Trivy: %s", job_name)
    return {"job": job_name}


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
