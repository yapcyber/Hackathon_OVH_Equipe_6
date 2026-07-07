# Dossier technique — Chaîne d'audit et de remédiation GitOps sécurisée

Hackathon OVHcloud x Ynov Campus — Équipe 6

Ce document détaille **chaque choix d'outil, chaque décision d'architecture, et chaque incident rencontré et résolu** pendant l'implémentation. Objectif : pouvoir répondre à n'importe quelle question du jury sur le "pourquoi" et le "comment" de chaque brique.

---

## 1. Contraintes du brief et périmètre

Le brief impose une stack strictement limitée à des projets CNCF :
Argo CD, Kyverno, Falco, Prometheus, plus un audit (Kubescape *ou* Trivy), et la couche IA via OVHcloud AI Endpoints.

Règle non négociable : **aucune remédiation automatique n'est appliquée sur le cluster**. L'IA détecte, analyse, propose un correctif sous forme de Pull Request. Un humain review et merge. Argo CD ne fait que se resynchroniser sur ce que Git dit — jamais l'inverse.

---

## 2. Choix des outils et justification

### 2.0 Tableau récapitulatif du statut CNCF

Le brief impose une stack "strictement CNCF" — voici le statut réel de maturité de chaque brique (vérifié sur `cncf.io` / annonces officielles, pas approximatif) :

| Outil | Rôle dans notre architecture | Statut CNCF | Repère |
|---|---|---|---|
| **Argo CD** | Synchronisation GitOps | **Graduated** | Incubating 26/03/2020 → Graduated 06/12/2022 |
| **Kyverno** | Policy-as-code (admission) | **Graduated** | Incubating 13/07/2022 → Graduated 16/03/2026 (très récent) |
| **Falco** | Détection runtime (syscalls) | **Graduated** | Incubating 08/01/2020 → Graduated 29/02/2024 |
| **Prometheus** | Observabilité / métriques | **Graduated** | 2ᵉ projet CNCF gradué (après Kubernetes), le 09/08/2018 |
| **Trivy (Operator)** | Audit de sécurité (images/config) | **Hors gouvernance CNCF** | Projet Aqua Security, listé dans le CNCF Cloud Native Landscape mais pas hébergé par la CNCF |
| *(alternative non retenue)* Kubescape | Audit de sécurité | Incubating | Accepté CNCF en 2022 — seule alternative "vraiment CNCF" à Trivy pour ce rôle |
| OVHcloud AI Endpoints | Couche IA (génération de correctifs) | Hors périmètre CNCF | Service cloud propriétaire, imposé par le brief (souveraineté numérique) |

**Point de transparence assumé devant le jury** : le brief propose « Kubescape *ou* Trivy » comme si les deux étaient équivalents côté CNCF — ce n'est pas le cas. Trivy (Aqua Security) n'est pas un projet hébergé par la CNCF, contrairement à Kubescape qui est en *Incubating*. Nous avons choisi Trivy Operator malgré ça pour des raisons techniques concrètes (voir §2.3 : webhook natif, CRD persistants) — un compromis pragmatique explicite, pas une méconnaissance du statut réel des projets.

### 2.1 Argo CD (synchronisation GitOps) — pas de débat, imposé par le brief
Choix d'implémentation : **pattern "app-of-apps"**. Une seule Application racine (`infra-app-of-apps`) pointe vers `infra/argocd/applications/` dans le repo Git ; ce dossier contient les manifestes `Application` de chaque brique (Kyverno, Falco, Trivy Operator, Prometheus, moteur IA, workload de démo). Avantage : un seul point d'entrée bootstrap (`kubectl apply -f infra/argocd/applications/app-of-apps.yaml`), tout le reste se déploie en cascade depuis Git.

Chaque `Application` a `syncPolicy.automated.{prune,selfHeal}: true` : Argo CD supprime ce qui n'est plus dans Git et **annule toute modification manuelle** faite directement sur le cluster (voir §6 "Incidents" — on s'est fait piéger par ça nous-mêmes).

### 2.2 Kyverno (policy-as-code) — choisi plutôt qu'OPA/Gatekeeper
Raison : policies natives en YAML (pas de langage Rego à apprendre), CRD `ClusterPolicy` directement lisible par un non-spécialiste — plus adapté à une démo devant un jury qui doit comprendre la policy en un coup d'œil.

5 `ClusterPolicy` livrées (`infra/kyverno/policies/`) :

| Policy | Mode | Ce qu'elle détecte |
|---|---|---|
| `disallow-privileged-containers` | **Enforce** | `securityContext.privileged: true` — bloqué à l'admission |
| `disallow-latest-tag` | Audit | Image sans tag explicite, ou taguée `:latest` |
| `disallow-host-path` | Audit | Volume `hostPath` (évasion de conteneur triviale) |
| `require-run-as-nonroot` | Audit | Conteneur sans `runAsNonRoot: true` |
| `require-resource-limits` | Audit | Conteneur sans `resources.limits.{cpu,memory}` |

Une seule policy en `Enforce` (testée en conditions réelles : `kubectl run` avec `securityContext.privileged: true` → rejeté par le webhook d'admission Kyverno avant même d'atteindre un node). Les 4 autres sont volontairement en **`Audit`** : elles ne bloquent jamais `vulnerable-demo`, dont le rôle est justement de rester déployable tout en cumulant ces 4 défauts (`nginx:latest`, `runAsUser: 0`, `hostPath: /`, aucune limite de ressources) pour déclencher Trivy/Falco. Chaque policy a été validée avec `kyverno apply infra/kyverno/policies/ --resource apps/vulnerable-demo/deployment.yaml` avant commit : les 4 policies Audit échouent bien sur ce manifeste (`fail: 4`), preuve qu'elles détectent réellement ce qu'elles annoncent, pas juste une CRD qui existe sans jamais matcher. `background: true` sur toutes : elles auditent aussi les ressources déjà existantes, pas seulement les nouvelles admissions.

### 2.3 Trivy Operator — choisi plutôt que Kubescape
Le brief laissait le choix. Trivy Operator a été préféré car :
- il tourne en continu dans le cluster (CRD `VulnerabilityReport` / `ConfigAuditReport` mis à jour automatiquement), alors que Kubescape est plus orienté scan ponctuel/CLI ;
- il expose un `webhookBroadcastURL` natif — branchement direct sur notre moteur IA sans code de polling à écrire ;
- écosystème Aqua Security bien maintenu, chart Helm officiel simple à intégrer via Argo CD.

### 2.4 Falco (détection runtime)
Déployé avec le driver **`modern_ebpf`** plutôt que le driver noyau classique (`kmod`) — pas de compilation de module noyau nécessaire, compatible out-of-the-box avec les nodes OVHcloud (Ubuntu 22.04, kernel 5.15). `falcosidekick` activé en sidecar pour transformer les alertes Falco en webhook HTTP vers notre moteur (sans lui, Falco ne fait que logguer en stdout).

### 2.5 Prometheus (kube-prometheus-stack)
Chart standard `kube-prometheus-stack` (Prometheus + Grafana + kube-state-metrics + node-exporter + Alertmanager). Choisi car c'est le chart de référence de la communauté Prometheus Operator, avec ServiceMonitor auto-découverte — cohérent avec l'esprit "déclaratif" du reste de la stack.

**Observabilité du moteur IA lui-même** (pas seulement du cluster) : `webhook_receiver.py` expose `/metrics` (scrapé via `k8s/servicemonitor.yaml`) avec des compteurs `ai_remediation_alerts_received_total`, `ai_remediation_alerts_ignored_total{reason}`, `ai_remediation_jobs_created_total` et `ai_remediation_job_outcomes_total{outcome}` + un histogramme `ai_remediation_ai_call_duration_seconds`. Problème spécifique résolu : les `Job` de remédiation sont éphémères (quelques secondes à minutes) et ne peuvent pas être scrapés directement par Prometheus — chaque `Job` pousse donc son résultat (succès/échec, latence de l'appel IA) au webhook via un endpoint interne `/internal/job-metrics` (`job_runner/metrics.py`, best-effort, un échec de reporting ne fait jamais échouer le `Job`), plutôt que de déployer un Pushgateway supplémentaire.

Trois dashboards Grafana provisionnés en GitOps (`infra/argocd/applications/prometheus.yaml` + `infra/prometheus/dashboards/`) : Trivy Operator et Falco importés depuis grafana.com par ID (`17813`, `11914`, pas de JSON à maintenir), et un dashboard custom "Boucle de remédiation IA" sur nos métriques (alertes reçues/ignorées, Jobs créés, PR ouvertes, latence IA).

### 2.6 OVHcloud AI Endpoints (couche IA)
Modèle utilisé : **`Meta-Llama-3_3-70B-Instruct`**, appelé via l'API compatible OpenAI d'OVHcloud.
URL réelle (après correction, voir incident §6.4) : `https://oai.endpoints.kepler.ai.cloud.ovh.net/v1/chat/completions`.
Authentification : `Authorization: Bearer <clé fournie par OVHcloud>`, stockée uniquement dans un Secret Kubernetes (`ai-endpoints-credentials`), jamais en clair dans Git.

---

## 3. Architecture du dépôt GitOps

```
Hackathon_OVH_Equipe_6/
├── infra/                          # Outils CNCF, gérés par Argo CD (app-of-apps)
│   ├── argocd/
│   │   ├── projects/                # AppProject : RBAC Argo CD + whitelist des repos sources autorisés
│   │   └── applications/            # 1 fichier = 1 Application Argo CD
│   ├── kyverno/policies/             # ClusterPolicy (policy-as-code)
│   ├── falco/, trivy/, prometheus/   # values.yaml de référence (doc — les vraies values sont inline dans les Application)
├── apps/vulnerable-demo/            # Workload volontairement vulnérable, pour déclencher la démo
├── ai-remediation-engine/           # Notre code : webhook + Job d'enrichissement/IA/PR
│   ├── src/webhook_receiver.py       # Deployment stateless, point d'entrée Falcosidekick/Trivy
│   ├── src/job_runner/               # Code exécuté par chaque Job éphémère
│   ├── k8s/                          # Manifestes K8s du moteur (RBAC, Deployment, namespace)
│   └── Dockerfile
└── docs/
    ├── architecture.md               # Diagramme de séquence Mermaid
    └── demo-runbook.sh                # Script de démo interactif
```

**Séparation logique délibérée** : `infra/` (outils CNCF, jamais de code métier) / `apps/` (charge de travail de démo, volontairement isolée du reste) / `ai-remediation-engine/` (notre seul code applicatif) / `docs/` (tout ce qui sert à expliquer/démontrer, pas à faire tourner le cluster).

---

## 4. Le moteur de remédiation IA — architecture détaillée

### 4.1 Décision : Deployment (ingestion) + Job Kubernetes (traitement), pas un script unique

Question posée dans le brief : script Python derrière un webhook, ou Jobs Kubernetes ? Réponse : **les deux, avec des responsabilités séparées**.

| Composant | Type K8s | Rôle | Durée de vie |
|---|---|---|---|
| `webhook_receiver.py` | Deployment (1 replica, toujours actif) | Reçoit Falcosidekick/Trivy, filtre, dédoublonne, crée un Job | Permanent |
| `job_runner/*.py` | Job (1 par alerte traitée) | Enrichissement → appel IA → ouverture PR | Éphémère (TTL 1h après complétion) |

Justification de cette séparation :
- **Isolation des credentials** : le Deployment webhook (exposé en permanence, donc plus surface d'attaque) ne détient **aucun secret sensible**. Seul le Job éphémère reçoit le Bearer token AI Endpoints et le token GitHub, et ne vit que le temps de traiter une alerte.
- **Auditabilité** : chaque remédiation = un Job nommé, avec ses propres logs consultables individuellement (`kubectl logs job/remediate-...`).
- **Résilience** : retry natif Kubernetes (`backoffLimit: 2`) sans avoir à réimplémenter de la logique de retry.
- **Least privilege distinct par composant** : RBAC du webhook = `create` sur `Jobs` uniquement. RBAC du Job = `get/list/watch` en lecture seule sur les workloads (pour construire le contexte envoyé à l'IA) — **aucun verbe d'écriture** sur le cluster.

### 4.2 Pipeline exact d'un Job de remédiation

1. **`enrichment.py`** : parse le payload JSON de l'alerte (Falco ou Trivy), résout le namespace/name/kind **réel** de la ressource visée (Falco : `output_fields` puis remontée Pod → ReplicaSet → Deployment ; Trivy : labels `trivy-operator.resource.*` du CR `VulnerabilityReport`), va lire (lecture seule, RBAC dédié) le manifeste K8s correspondant pour donner du contexte, construit un prompt structuré.
2. **`ai_client.py`** : `POST https://oai.endpoints.kepler.ai.cloud.ovh.net/v1/chat/completions` avec le modèle `Meta-Llama-3_3-70B-Instruct`, `temperature: 0.2` (réponses reproductibles, pas créatives), prompt système qui interdit explicitement à l'IA de proposer une commande à exécuter directement — l'IA doit renvoyer le **manifeste YAML complet et corrigé** (pas un diff partiel), dans le tout premier bloc ` ```yaml ` de sa réponse.
3. **`main.py`** : extrait ce premier bloc YAML de la réponse IA (regex sur les fences ` ```yaml `).
4. **`validation.py`** : valide structurellement ce manifeste avec **`kubeconform -strict`** (schémas Kubernetes officiels, 100% local — pas d'appel au cluster). Si invalide, le `Job` échoue et **aucune PR n'est ouverte**. Volontairement pas de `kubectl apply --dry-run=server` : Kubernetes exige le verbe d'écriture réel même en dry-run, ce qui aurait cassé l'invariant central du projet (RBAC du `Job` strictement `get/list/watch`).
5. **`pr_generator.py`** : clone le repo (`git clone --depth 1`), crée une branche `ai-remediation/<source>-<fingerprint>`, **écrase le fichier GitOps existant** correspondant à la cible résolue en (1) — cible vérifiée contre une whitelist explicite `KNOWN_REMEDIATION_TARGETS` (namespace, name) → chemin, jamais dérivée directement du payload — commit, **push**, puis appelle l'API GitHub `POST /repos/.../pulls` avec **`draft: true`**.

Le fichier écrasé est déjà référencé dans le `kustomization.yaml` de l'app GitOps concernée : après merge humain, Argo CD applique donc réellement le correctif au prochain sync (contrairement à une première version qui écrivait un fichier séparé jamais inclus dans les `resources:` de Kustomize — le correctif n'était alors jamais appliqué, seulement présent dans Git).

### 4.3 Filtrage anti-boucle (leçon apprise en production, voir incident §6.2)

Le webhook ignore systématiquement :
- toute alerte Trivy dont `kind != VulnerabilityReport` (donc les `ConfigAuditReport`, sources du bug de boucle infinie rencontré),
- toute alerte dont le namespace n'est pas `demo` (`WATCHED_NAMESPACE`), avec une liste explicite de namespaces système toujours ignorés (`remediation`, `kube-system`, `argocd`, `kyverno`, `trivy-system`, `monitoring`, `falco`) pour éviter que notre propre stack de sécurité ne s'auto-déclenche.

Déduplication : fingerprint SHA-256 sur `rule` (Falco) ou `metadata.name` (Trivy), fenêtre de 300s, pour éviter un Job par répétition de la même alerte.

### 4.4 Robustesse : idempotence, retry, tests automatisés

- **Idempotence des PR** : un retry Kubernetes (`backoffLimit: 2`) réutilise le même `FINGERPRINT` (propagé par le webhook, pas recalculé depuis `HOSTNAME`) donc la même branche `ai-remediation/<source>-<fingerprint>`. Avant tout `git clone`, `pr_generator.py` interroge l'API GitHub (`GET /pulls?head=...&state=open`) : si une PR est déjà ouverte pour cette branche, elle est retournée telle quelle — aucun nouveau clone/commit/push. Le `push` final utilise `--force` (branche exclusivement possédée par le bot, jamais touchée par un humain) pour absorber une tentative précédente avortée avant l'ouverture de la PR.
- **Retry sur l'appel IA** : `ai_client.py` retente automatiquement (backoff exponentiel, 3 tentatives par défaut) sur `429` et `5xx` — jamais sur les erreurs `4xx` (une erreur de requête ne se résout pas en réessayant).
- **Parsing tolérant de la réponse IA** : `_extract_yaml_block` (main.py) ne prend plus aveuglément le premier bloc de code de la réponse — il prend le premier bloc qui parse comme un manifeste Kubernetes valide (dict avec une clé `kind`), tolérant sur la casse/présence de l'étiquette de langage (` ```yaml `, ` ```yml `, ` ```YAML `, ou nue).
- **Tests unitaires** (`ai-remediation-engine/tests/`, 29 tests, `pytest`) : fingerprint/déduplication, authentification webhook, extraction du bloc YAML, résolution namespace/name/kind par source, fallback de `resolve_owning_deployment`, idempotence de `pr_generator`, retry de `ai_client`. Aucun test ne touche un vrai cluster ou le réseau (mocks `httpx.MockTransport`, monkeypatching).

---

## 5. Garanties de sécurité (Livrable 4)

| Garantie | Mécanisme concret |
|---|---|
| Aucun merge automatique | `pr_generator.py` ouvre systématiquement en `draft: true`, sur une branche dédiée, jamais sur `main` |
| Token PR bot limité | Scope strict recommandé : `Contents: write` + `Pull requests: write` sur le repo uniquement — jamais de droit d'administration, jamais de merge |
| Le Job ne peut rien écrire sur le cluster | `ClusterRole ai-remediation-job-readonly` : verbes `get/list/watch` uniquement, sur `pods/deployments/policyreports/vulnerabilityreports` |
| Le webhook ne peut créer que des Jobs | `Role ai-remediation-webhook` : `create/get/list` sur `batch/jobs` dans son propre namespace, rien d'autre |
| Seul Argo CD applique un changement au cluster | Toujours après merge humain du diff proposé — jamais avant |
| Policy Kyverno de base | `disallow-privileged-containers` en `Enforce`, testée en direct |
| PR jamais ouverte si YAML invalide | `kubeconform -strict` en local dans le `Job` (§4.2) — sans étendre le RBAC read-only |
| Défauts connus du workload audités | 4 policies Kyverno Audit (`disallow-latest-tag`, `disallow-host-path`, `require-run-as-nonroot`, `require-resource-limits`) |
| Jobs et webhook durcis | `securityContext` complet (non-root, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`) sur le webhook **et** les Jobs (`/tmp` en `emptyDir` pour `git clone`/`kubeconform`) |
| Accès réseau au webhook restreint | `NetworkPolicy` : seuls `falco`, `trivy-system` (alertes) et `monitoring` (scrape `/metrics`) peuvent atteindre le webhook — tout le reste du cluster est refusé par défaut dès qu'une `NetworkPolicy` sélectionne le Pod |
| Authentification applicative optionnelle | Secret partagé (`WEBHOOK_SHARED_TOKEN`, header `X-Webhook-Token`) — désactivée par défaut tant que le secret n'est pas créé et câblé côté Falcosidekick/Trivy Operator (voir README), pour ne jamais casser le pipeline existant |
| Périmètre Argo CD resserré | `AppProject.destinations` énumère les 7 namespaces réellement utilisés (plus de `namespace: "*"`) |
| Régression Kyverno testée en CI | `kyverno apply` contre `vulnerable-demo` doit rester à `pass: 2, fail: 4` — la CI échoue si une policy casse silencieusement |

---

## 6. Incidents rencontrés pendant le déploiement (et ce qu'ils révèlent)

Cette section documente les vrais problèmes rencontrés en déployant sur le cluster réel OVHcloud — utile pour montrer au jury une compréhension réelle de l'infra, pas juste du code qui marche "sur le papier".

### 6.1 CRD Kyverno trop volumineux pour `kubectl apply` classique
`clusterpolicies.kyverno.io` et `policies.kyverno.io` dépassent la limite de 262 144 octets pour l'annotation `last-applied-configuration` utilisée par l'apply client-side classique. **Solution** : `syncOptions: [ServerSideApply=true]` sur l'Application Argo CD de Kyverno (et `kubectl apply --server-side` en intervention manuelle). Le même problème existe pour les CRD d'Argo CD lui-même à l'installation.

### 6.2 Boucle auto-référentielle Trivy ↔ moteur de remédiation
Au premier déploiement du webhook, Trivy Operator scanne (audit de configuration) les **propres Jobs de remédiation** créés par notre moteur, génère un `ConfigAuditReport`, qui déclenche un nouveau webhook, qui crée un nouveau Job, qui se fait auditer à son tour → croissance quasi exponentielle (**237 puis plus de 1600 Jobs créés en quelques minutes**). Root cause : aucun filtrage de namespace/type de rapport dans la version initiale du webhook. **Correction** : filtrage strict par `kind` et par namespace (voir §4.3). Confinement d'urgence pendant l'incident : `scale --replicas=0` sur le Deployment webhook + désactivation temporaire de `selfHeal` sur les Applications Argo CD parentes (qui sinon annulaient le scale-down).

### 6.3 Falco bloqué par sa propre ClusterPolicy
Le DaemonSet Falco, avec le driver `kmod`/`ebpf` classique, nécessite `securityContext.privileged: true` — exactement ce que notre policy `disallow-privileged-containers` interdit. **Correction** : `driver.kind: modern_ebpf` + `driver.modernEbpf.leastPrivileged: true`, qui remplace `privileged: true` par des capabilities Linux ciblées (`BPF`, `SYS_RESOURCE`, `PERFMON`, `SYS_PTRACE`) — Falco tourne désormais en conformité avec sa propre policy de sécurité.

### 6.4 URL AI Endpoints incorrecte dans un premier temps
Le format `https://endpoints.ai.cloud.ovh.net/{model}/api/openai_compat/v1/chat/completions` supposé initialement redirige (301) vers la page catalogue publique — mauvaise URL. La bonne URL, unifiée pour tous les modèles, est `https://oai.endpoints.kepler.ai.cloud.ovh.net/v1/chat/completions` (compatible OpenAI, modèle spécifié dans le corps JSON, pas dans le path).

### 6.5 selfHeal d'Argo CD qui annule des interventions manuelles
Plusieurs correctifs appliqués directement via `kubectl apply` sur des ressources gérées par Argo CD (`Application` elles-mêmes, `Deployment` du webhook) ont été **silencieusement annulés** quelques secondes/minutes après par le `selfHeal` — tant que le correctif n'était pas commité dans Git, Argo CD le considérait comme une dérive à corriger. Illustre concrètement pourquoi le repo Git est la seule source de vérité dans cette architecture, et pourquoi toute intervention "à la main" sur le cluster est fragile par construction.

### 6.6 Image Docker : utilisateur root, `git` manquant
Le premier build de l'image du moteur IA (`python:3.12-slim`) tournait en root par défaut → rejeté par `securityContext.runAsNonRoot: true` du Deployment. Ajout d'un utilisateur non-root (`USER 1000`). Deuxième itération : `git` absent de l'image de base, nécessaire pour `pr_generator.py` (`git clone`/`commit`/`push`) → ajout via `apt-get install git` dans le Dockerfile.

### 6.7 Scope de token GitHub — moindre privilège en pratique
Un premier token "fine-grained" fourni pour ouvrir les PR s'est révélé invalide (401 côté API GitHub). Un token "classic" avec scope `write:packages` a permis de débloquer le push d'image GHCR, mais s'est avéré avoir des **droits admin complets** sur le compte (créé sans scope restreint) — utilisé ponctuellement pour valider la boucle de bout en bout puis **révoqué immédiatement après test**, remplacé par un Fine-Grained PAT correctement scopé (`Contents: write` + `Pull requests: write`, ce repo uniquement). Le package GHCR a ensuite été rendu **public** (le code y étant de toute façon déjà public sur GitHub), ce qui supprime le besoin de tout `imagePullSecret` côté cluster — une dépendance de moins à un token qui peut expirer/être révoqué.

---

## 7. Preuve de fonctionnement (test réel effectué)

Test de bout en bout exécuté sur le cluster réel (pas un mock) :
1. Payload Falco simulé (namespace `demo`, règle "Terminal shell in container") envoyé au webhook.
2. Job créé automatiquement, RBAC lecture seule vérifié.
3. Appel réel à `oai.endpoints.kepler.ai.cloud.ovh.net` → **`200 OK`**, réponse IA reçue (~1000 caractères).
4. Branche créée, commit poussé, **Pull Request #1 ouverte en `draft`** sur `yapcyber/Hackathon_OVH_Equipe_6` — vérifié via l'API GitHub (`draft: true`, `state: open`).
5. Aucune action automatique au-delà de l'ouverture de la PR — merge fait/refusé manuellement par un humain de l'équipe.

---

## 8. Dette technique connue (assumée, non bloquante)

- Les CronJobs internes `kyverno-cleanup-*` (fournis par le chart Kyverno lui-même, pas notre code) restent en `ImagePullBackOff` — n'affecte pas le fonctionnement de la policy engine (`ClusterPolicy` reste `Ready`/`Enforce`).
- 5 `ClusterPolicy` livrées (§2.2) — extensible plus loin (ex: `disallow-capabilities`, `require-non-root-group`, etc.), mais couvre déjà les 4 défauts volontaires de `vulnerable-demo`.
- **Secrets K8s en clair (pas de External Secrets Operator)** : `ai-endpoints-credentials`, `git-pr-credentials`, `webhook-shared-token` restent des `Secret` Kubernetes classiques (base64, pas chiffrés), créés hors GitOps via `kubectl create secret`. ESO a été explicitement envisagé (§ punch-list P4) mais **non implémenté** : brancher un `SecretStore` ESO nécessite un backend externe réel (Vault, un coffre géré OVHcloud, etc.) que l'équipe n'a pas provisionné pendant le hackathon — déployer une Application ESO pointant vers un backend inexistant aurait été un manifeste qui ne synchronise jamais, donc pire qu'assumer la dette explicitement. Décision consciente : mieux vaut un `Secret` en clair documenté que de la fausse conformité GitOps.
- **`clusterResourceWhitelist`/`namespaceResourceWhitelist` de l'`AppProject` restent en `"*" "*"`** (voir `infra/argocd/projects/equipe-6-project.yaml`) : les 3 charts Helm tiers installent collectivement des dizaines de CRD (ServiceMonitor, PrometheusRule, Probe, ClusterPolicy, PolicyException, Alertmanager, ThanosRuler...) qu'on ne peut pas énumérer de façon fiable sans risquer de casser un sync la veille d'une démo. En contrepartie, `sourceRepos` (5 sources exactes) et `destinations` (7 namespaces exacts, plus de `"*"`) sont, eux, resserrés.
- **Authentification applicative du webhook optionnelle, pas activée par défaut** : le code (`WEBHOOK_SHARED_TOKEN`) et le `Secret` template existent, mais câbler la même valeur côté Falcosidekick/Trivy Operator est une étape manuelle documentée (README), volontairement hors GitOps pour ne jamais committer ce secret en clair dans une `Application`. La défense réellement active par défaut est la `NetworkPolicy` (§5).
- **Image du moteur toujours taguée `:latest`** (`webhook-deployment.yaml`, `JOB_IMAGE`) : la CI (`.github/workflows/ci.yml`) pousse maintenant systématiquement un tag immuable `sha-<commit>` en plus de `:latest`, mais le passage des manifestes à ce tag est un changement manuel restant (`:latest` fonctionne déjà et casser cette référence la veille d'une démo était jugé plus risqué que de le laisser tel quel pour l'instant).
- **Déduplication du webhook non persistante** : `_recent_fingerprints` est un `dict` en mémoire du process — perdu au redémarrage du Pod, et ne fonctionnerait pas avec plusieurs replicas (`replicas: 1` actuellement, donc non-problématique en l'état). Un Redis ou une `ConfigMap` partagée serait la vraie solution HA, non justifiée pour une démo mono-replica.

---

## 9. Comment rejouer la démo

Voir `docs/demo-runbook.sh` — script bash interactif, 6 phases (GitOps → Kyverno → Trivy → Falco → Prometheus → boucle IA complète), pensé pour être exécuté en direct devant le jury avec des pauses commentées à chaque étape.

---

## 10. CI et validation continue

`.github/workflows/ci.yml`, 4 jobs, exécutés à chaque push/PR sur `main` :

| Job | Ce qu'il vérifie |
|---|---|
| `unit-tests` | `pytest` sur `ai-remediation-engine/tests/` (29 tests, §4.4) |
| `validate-manifests` | `kubectl kustomize` + `kubeconform -strict` sur les deux Kustomization (`ai-remediation-engine/k8s`, `apps/vulnerable-demo`) et sur les manifestes bruts (Applications Argo CD, AppProject, ClusterPolicy Kyverno, dashboards Grafana) — schémas CRD via le catalogue communautaire `datreeio/CRDs-catalog` |
| `kyverno-policy-regression` | `kyverno apply` contre `vulnerable-demo` doit rester exactement à `pass: 2, fail: 4` — détecte une policy cassée silencieusement ou un `vulnerable-demo` "corrigé" sans mise à jour du test |
| `build-and-push` | Build + push `ghcr.io/.../ai-remediation-engine:latest` et `:sha-<commit>`, uniquement sur push vers `main`, après succès des 3 jobs précédents |

Chaque étape de cette CI a été validée manuellement en amont (pas juste écrite en espérant que ça marche) : build Docker réel, `pytest` réellement exécuté (29/29 passés), `kubeconform`/`kyverno apply` réellement lancés contre les manifestes du repo.
