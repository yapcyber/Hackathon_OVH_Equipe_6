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
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("webhook-receiver")

# Métriques exposées sur /metrics (scrapées via k8s/servicemonitor.yaml).
# Les Jobs de remédiation sont éphémères et ne peuvent pas être scrapés
# directement : ils reportent leur résultat au webhook via /internal/job-metrics
# (voir job_runner/metrics.py), qui est le seul composant durable du moteur.
ALERTS_RECEIVED = Counter(
    "ai_remediation_alerts_received_total", "Alertes reçues par le webhook", ["source"]
)
ALERTS_IGNORED = Counter(
    "ai_remediation_alerts_ignored_total",
    "Alertes ignorées avant création de Job (hors périmètre, doublon, mauvais type)",
    ["source", "reason"],
)
JOBS_CREATED = Counter(
    "ai_remediation_jobs_created_total", "Jobs de remédiation créés", ["source"]
)
JOB_OUTCOMES = Counter(
    "ai_remediation_job_outcomes_total",
    "Résultat final des Jobs de remédiation (rapporté par le Job lui-même)",
    ["source", "outcome"],
)
AI_CALL_DURATION = Histogram(
    "ai_remediation_ai_call_duration_seconds", "Latence de l'appel AI Endpoints", ["source"]
)

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
    ALERTS_RECEIVED.labels(source="falco").inc()
    ns = payload.get("output_fields", {}).get("k8s.ns.name")
    if ns in IGNORED_NAMESPACES or ns != WATCHED_NAMESPACE:
        ALERTS_IGNORED.labels(source="falco", reason="out_of_scope").inc()
        return Response(status_code=202, content=f"namespace '{ns}' hors périmètre, ignoré")
    fp = _fingerprint("falco", payload)
    if _is_duplicate(fp):
        ALERTS_IGNORED.labels(source="falco", reason="duplicate").inc()
        return Response(status_code=202, content="duplicate, ignored")
    job_name = _create_remediation_job("falco", fp, payload)
    JOBS_CREATED.labels(source="falco").inc()
    log.info("Job créé depuis alerte Falco: %s", job_name)
    return {"job": job_name}


@app.post("/webhook/trivy")
async def trivy_webhook(request: Request):
    payload = await request.json()
    ALERTS_RECEIVED.labels(source="trivy").inc()
    if payload.get("kind") != "VulnerabilityReport":
        ALERTS_IGNORED.labels(source="trivy", reason="wrong_kind").inc()
        return Response(status_code=202, content="rapport non-VulnerabilityReport, ignoré")
    ns = payload.get("metadata", {}).get("namespace")
    if ns in IGNORED_NAMESPACES or ns != WATCHED_NAMESPACE:
        ALERTS_IGNORED.labels(source="trivy", reason="out_of_scope").inc()
        return Response(status_code=202, content=f"namespace '{ns}' hors périmètre, ignoré")
    fp = _fingerprint("trivy", payload)
    if _is_duplicate(fp):
        ALERTS_IGNORED.labels(source="trivy", reason="duplicate").inc()
        return Response(status_code=202, content="duplicate, ignored")
    job_name = _create_remediation_job("trivy", fp, payload)
    JOBS_CREATED.labels(source="trivy").inc()
    log.info("Job créé depuis rapport Trivy: %s", job_name)
    return {"job": job_name}


class JobMetricReport(BaseModel):
    """Payload poussé par un Job éphémère en fin d'exécution (best-effort,
    voir job_runner/metrics.py). Le Job n'a aucun droit d'écriture cluster ;
    ceci est un simple POST HTTP interne au service, pas une action sur le
    cluster."""

    source: str
    outcome: str  # pr_opened | ai_error | no_yaml_block | pr_error
    ai_call_seconds: float | None = None


@app.post("/internal/job-metrics")
async def job_metrics(report: JobMetricReport):
    JOB_OUTCOMES.labels(source=report.source, outcome=report.outcome).inc()
    if report.ai_call_seconds is not None:
        AI_CALL_DURATION.labels(source=report.source).observe(report.ai_call_seconds)
    return Response(status_code=204)


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
