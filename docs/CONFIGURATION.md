# Inventaire de configuration

Référence rapide : **quoi est installé, avec quelle version, quelle config, dans quel namespace.**
Le "pourquoi" de chaque choix est dans `DOSSIER_TECHNIQUE.md` (§2) — ce document-ci ne
justifie rien, il liste des faits vérifiables directement dans les fichiers cités.

---

## 1. Vue d'ensemble

| Outil | Rôle | Namespace | Source (chart/repo) | Version épinglée | Sync policy Argo CD |
|---|---|---|---|---|---|
| Argo CD | GitOps (déjà installé sur le cluster, pas géré par lui-même) | `argocd` | — | — | — |
| Kyverno | Policy-as-code | `kyverno` | `kyverno.github.io/kyverno` | `3.2.6` | auto, prune, selfHeal, `ServerSideApply=true` |
| 5 `ClusterPolicy` Kyverno | Policy-as-code (règles) | (cluster-scoped) | ce repo, `infra/kyverno/policies/` | — | auto, prune, selfHeal |
| Falco | Détection runtime | `falco` | `falcosecurity.github.io/charts` | `9.1.0` | auto, prune, selfHeal |
| Trivy Operator | Audit vulnérabilités/config | `trivy-system` | `aquasecurity.github.io/helm-charts` | `0.24.1` | auto, prune, selfHeal |
| kube-prometheus-stack | Observabilité | `monitoring` | `prometheus-community.github.io/helm-charts` | `62.5.1` | auto, prune, selfHeal |
| Dashboards Grafana custom | Observabilité (ConfigMaps) | `monitoring` | ce repo, `infra/prometheus/dashboards/` | — | auto, prune, selfHeal |
| AI Remediation Engine | Webhook + Job IA/PR | `remediation` | ce repo, `ai-remediation-engine/k8s/` | image `ghcr.io/yapcyber/ai-remediation-engine:latest` | auto, prune, selfHeal, sync-wave `1` |
| vulnerable-demo | Workload de démo (volontairement non conforme) | `demo` | ce repo, `apps/vulnerable-demo/` | image `nginx:latest` | auto, prune, selfHeal |
| OVHcloud AI Endpoints | Modèle IA (service externe, hors cluster) | — | — | modèle `Meta-Llama-3_3-70B-Instruct` | — |

Bootstrap unique : `kubectl apply -f infra/argocd/applications/app-of-apps.yaml` (Application `infra-app-of-apps`, pattern app-of-apps — voir `DOSSIER_TECHNIQUE.md` §2.1).

---

## 2. Argo CD

- **AppProject** : `equipe-6` (`infra/argocd/projects/equipe-6-project.yaml`)
  - `sourceRepos` : 5 exactement — ce repo Git + les 3 dépôts de charts Helm (Kyverno, Falco, Trivy) + le repo de charts Prometheus community.
  - `destinations` : 7 namespaces exacts (`argocd`, `kyverno`, `falco`, `trivy-system`, `monitoring`, `remediation`, `demo`) — plus de `namespace: "*"`.
  - `clusterResourceWhitelist` / `namespaceResourceWhitelist` : `"*" "*"` (dette assumée, voir `DOSSIER_TECHNIQUE.md` §8 — les 3 charts Helm installent trop de CRD différents pour une whitelist fiable par `kind`).
  - `roles` : 1 rôle `readonly` (lecture seule sur les Applications du projet, pour la démo/jury).
- **9 `Application`** au total (8 métier + 1 app-of-apps racine), toutes avec `syncPolicy.automated: {prune: true, selfHeal: true}`.
- **Sync waves** : `ai-remediation-engine` et `grafana-dashboards` sont en wave `"1"` (les CRD `ServiceMonitor` qu'elles utilisent viennent de kube-prometheus-stack, wave par défaut `0`).

---

## 3. Kyverno

Chart `kyverno` v`3.2.6`, `syncOptions: [CreateNamespace=true, ServerSideApply=true]` (les CRD `ClusterPolicy` dépassent la limite d'annotation en apply client-side classique).

| ClusterPolicy | Mode | Détecte |
|---|---|---|
| `disallow-privileged-containers` | **Enforce** | `securityContext.privileged: true` |
| `disallow-latest-tag` | Audit | Image sans tag, ou taguée `:latest` |
| `disallow-host-path` | Audit | Volume `hostPath` |
| `require-run-as-nonroot` | Audit | Conteneur sans `runAsNonRoot: true` |
| `require-resource-limits` | Audit | Conteneur sans `resources.limits.{cpu,memory}` |

Toutes en `background: true` (audit aussi les ressources déjà existantes, pas seulement à l'admission).

---

## 4. Falco

Chart `falco` v`9.1.0`, namespace `falco`.

| Paramètre | Valeur |
|---|---|
| `driver.kind` | `modern_ebpf` |
| `driver.modernEbpf.leastPrivileged` | `true` (capabilities ciblées `BPF`/`SYS_RESOURCE`/`PERFMON`/`SYS_PTRACE` au lieu de `privileged: true`) |
| `falcosidekick.enabled` | `true` |
| `falcosidekick.config.webhook.address` | `http://ai-remediation-webhook.remediation.svc.cluster.local:8080/webhook/falco` |

---

## 5. Trivy Operator

Chart `trivy-operator` v`0.24.1`, namespace `trivy-system`.

| Paramètre | Valeur |
|---|---|
| `trivy.ignoreUnfixed` | `true` (pas de PR pour une CVE sans correctif publié) |
| `operator.webhookBroadcastURL` | `http://ai-remediation-webhook.remediation.svc.cluster.local:8080/webhook/trivy` |
| Sévérités scannées (référence, `infra/trivy/values.yaml`) | `CRITICAL,HIGH` |

---

## 6. kube-prometheus-stack

Chart `kube-prometheus-stack` v`62.5.1`, namespace `monitoring`.

| Paramètre | Valeur |
|---|---|
| `prometheus.prometheusSpec.retention` | `15d` |
| `prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues` | `false` |
| `grafana.enabled` | `true` |
| `grafana.defaultDashboardsEnabled` | `true` |
| `grafana.sidecar.dashboards.enabled` | `true` (label `grafana_dashboard: "1"`) |
| Dashboards importés (`gnetId` grafana.com) | Trivy Operator `17813`, Falco `11914` |
| Dashboard custom | "Boucle de remédiation IA" — ConfigMap `infra/prometheus/dashboards/ai-remediation-loop-configmap.yaml` |

---

## 7. AI Remediation Engine (`remediation`)

### 7.1 Composants et RBAC

| ServiceAccount | Type de charge | Droits RBAC | Détient les secrets ? |
|---|---|---|---|
| `ai-remediation-webhook` | `Deployment` (1 replica, permanent) | `Role` : `create/get/list` sur `batch/jobs`, namespace `remediation` uniquement | Non |
| `ai-remediation-job` | `Job` (1 par alerte, éphémère) | `ClusterRole` : `get/list/watch` sur `pods/deployments/replicasets/jobs/namespaces`, `policyreports/clusterpolicyreports`, `vulnerabilityreports/configauditreports` — **aucun verbe d'écriture** | Oui (montés uniquement ici) |

### 7.2 Secrets requis (`k8s/secrets.example.yaml`, jamais commités réellement)

| Secret | Clé | Usage | Obligatoire ? |
|---|---|---|---|
| `ai-endpoints-credentials` | `token` | Bearer token OVHcloud AI Endpoints | Oui |
| `git-pr-credentials` | `token` | Token Git, scope `pull-requests: write` uniquement | Oui |
| `webhook-shared-token` | `token` | Auth optionnelle `X-Webhook-Token` sur `/webhook/*` | Non (`optional: true`, désactivée par défaut) |

### 7.3 `Deployment` webhook

| Paramètre | Valeur |
|---|---|
| Replicas | `1` |
| Image | `ghcr.io/yapcyber/ai-remediation-engine:latest` |
| Ressources | requests `50m`/`64Mi`, limits `200m`/`128Mi` |
| `securityContext` | `runAsNonRoot`, `allowPrivilegeEscalation: false`, `privileged: false`, `readOnlyRootFilesystem: true` |
| Probes | liveness+readiness sur `GET /healthz` (délais 5s/3s) |
| Endpoints exposés | `POST /webhook/falco`, `POST /webhook/trivy`, `GET /metrics`, `POST /internal/job-metrics`, `GET /healthz` |

### 7.4 `Job` de remédiation (par alerte)

| Paramètre | Valeur |
|---|---|
| `backoffLimit` | `2` |
| `ttlSecondsAfterFinished` | `3600` |
| Ressources | requests `100m`/`128Mi`, limits `500m`/`256Mi` |
| `securityContext` (pod + conteneur) | `runAsNonRoot`, `runAsUser: 1000`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true` |
| Volume | `emptyDir` monté sur `/tmp` (git clone + kubeconform ont besoin d'écrire) |

### 7.5 `NetworkPolicy` (`ai-remediation-webhook-ingress`)

Ingress autorisé vers le webhook (port `8080`) uniquement depuis : namespaces `falco`, `trivy-system`, `monitoring`. Tout le reste du cluster est refusé par défaut.

### 7.6 Variables d'environnement (webhook)

| Variable | Défaut | Rôle |
|---|---|---|
| `NAMESPACE` | `remediation` | Namespace où créer les Jobs |
| `JOB_IMAGE` | *(obligatoire)* | Image utilisée pour les Jobs |
| `DEDUP_TTL_SECONDS` | `300` | Fenêtre de déduplication des alertes |
| `WATCHED_NAMESPACE` | `demo` | Seul namespace applicatif surveillé |
| `WEBHOOK_SHARED_TOKEN` | *(vide = auth désactivée)* | Header `X-Webhook-Token` requis si défini |
| `AI_PRICE_EUR_PER_MTOKEN` | `0.67` | Prix par million de tokens, pour le calcul du coût cumulé |

### 7.7 Variables d'environnement (Job)

| Variable | Défaut | Rôle |
|---|---|---|
| `OVH_AI_ENDPOINTS_BASE_URL` | `https://oai.endpoints.kepler.ai.cloud.ovh.net/v1` | Base URL API IA |
| `OVH_AI_ENDPOINTS_MODEL` | `Meta-Llama-3_3-70B-Instruct` | Modèle utilisé |
| `GITHUB_API_URL` | `https://api.github.com` | API GitHub pour l'ouverture de PR |
| `FINGERPRINT` | propagé par le webhook | Identifiant de l'alerte (nom de branche/PR) |
| `WEBHOOK_METRICS_URL` | `http://ai-remediation-webhook.remediation.svc.cluster.local:8080/internal/job-metrics` | Reporting best-effort du résultat |
| `FREEZE_CONFIGMAP_NAMESPACE` | `remediation` | Namespace de la ConfigMap de code freeze |
| `FREEZE_CONFIGMAP_NAME` | `freeze-calendar` | Nom de la ConfigMap de code freeze |

Cibles de remédiation connues (whitelist `KNOWN_REMEDIATION_TARGETS`, `pr_generator.py`) : `(demo, vulnerable-demo)` → `apps/vulnerable-demo/deployment.yaml`, `(demo, log4shell-demo)` → `apps/log4shell-demo/deployment.yaml`.

### 7.7bis Analyse de risque business & calendrier de freeze

- **ConfigMap `freeze-calendar`** (namespace `remediation`, versionnée en GitOps, pas un secret) : clés `active` (`"true"`/`"false"`), `until` (date de fin), `reason`. Lue en lecture seule par le Job.
- **RBAC dédié** : `Role` namespacé `ai-remediation-job-configmaps` (`get`/`list` sur `configmaps`, namespace `remediation` uniquement) — délibérément pas un ClusterRole.
- **Criticité business** : label ou annotation `business-criticality` (`critical`/`high`/`medium`/`low`) sur le `Deployment` ciblé ; `unknown` si absent.

### 7.8 Métriques Prometheus exposées sur `/metrics`

| Métrique | Type | Labels |
|---|---|---|
| `ai_remediation_alerts_received_total` | Counter | `source` |
| `ai_remediation_alerts_ignored_total` | Counter | `source`, `reason` |
| `ai_remediation_jobs_created_total` | Counter | `source` |
| `ai_remediation_job_outcomes_total` | Counter | `source`, `outcome` |
| `ai_remediation_ai_call_duration_seconds` | Histogram | `source` |
| `ai_remediation_ai_tokens_total` | Counter | `source`, `type` (`prompt`/`completion`) |
| `ai_remediation_ai_cost_eur_total` | Counter | `source` |

### 7.9 Image & dépendances

| Élément | Version |
|---|---|
| Image de base | `python:3.12-slim` |
| `kubeconform` (validation locale, non-cluster) | `0.8.0` (SHA256 vérifié au build) |
| `fastapi` | `0.111.0` |
| `uvicorn[standard]` | `0.30.1` |
| `kubernetes` (client Python) | `29.0.0` |
| `httpx` | `0.27.0` |
| `prometheus-client` | `0.20.0` |
| `PyYAML` | `6.0.1` |
| Utilisateur du conteneur | `uid 1000` (non-root) |

---

## 8. Workloads de démo (`demo`)

| Workload | Image | Déclenche | Exposition réseau |
|---|---|---|---|
| `vulnerable-demo` | `nginx:latest` | Config : tag flottant, `runAsUser: 0`, `hostPath: /` (4 policies Kyverno Audit) | Aucune (pas de Service) |
| `log4shell-demo` | `ghcr.io/christophetd/log4shell-vulnerable-app@sha256:6f88430688108e512f7405ac3c73d47f5c370780b94182854ea2cddc6bd59929` | CVE réelle : `CVE-2021-44228` (log4j-core 2.14.1) via `VulnerabilityReport` Trivy | Aucune (pas de Service, `NetworkPolicy` deny-all ingress) |

Cibles enregistrées dans `KNOWN_REMEDIATION_TARGETS` (`ai-remediation-engine/src/job_runner/pr_generator.py`) : `(demo, vulnerable-demo)` → `apps/vulnerable-demo/deployment.yaml`, `(demo, log4shell-demo)` → `apps/log4shell-demo/deployment.yaml`.

---

## 9. CI (`.github/workflows/ci.yml`)

| Job | Outils épinglés |
|---|---|
| `unit-tests` | Python `3.12`, `pytest==8.2.2` |
| `validate-manifests` | `kubeconform 0.8.0` (même SHA256 que le Dockerfile), `kubectl` (dernière stable), catalogue CRD `datreeio/CRDs-catalog` |
| `kyverno-policy-regression` | `kyverno CLI 1.18.1` — assertion figée : `pass: 2, fail: 4` sur `vulnerable-demo` |
| `build-and-push` | `docker/build-push-action@v6` → `ghcr.io/.../ai-remediation-engine:latest` + `:sha-<commit>` |

---

## 10. Récapitulatif des namespaces

| Namespace | Créé par | Contenu |
|---|---|---|
| `argocd` | (pré-existant, hors GitOps) | Argo CD lui-même |
| `kyverno` | Application `kyverno` | Kyverno + les 5 `ClusterPolicy` |
| `falco` | Application `falco` | Falco (DaemonSet) + Falcosidekick |
| `trivy-system` | Application `trivy-operator` | Trivy Operator |
| `monitoring` | Application `kube-prometheus-stack` | Prometheus, Grafana, Alertmanager, dashboards custom |
| `remediation` | Application `ai-remediation-engine` | Webhook, RBAC, Secrets, NetworkPolicy, ServiceMonitor |
| `demo` | Application `vulnerable-demo` | Le workload volontairement vulnérable |
