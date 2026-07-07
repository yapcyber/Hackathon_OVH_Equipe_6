# AI Remediation Engine

Composant qui relie la détection (Falco/Trivy) à OVHcloud AI Endpoints et
ouvre une Pull Request de correctif — jamais de merge ni d'action directe
sur le cluster.

## Composants

- `src/webhook_receiver.py` — Deployment stateless, reçoit Falcosidekick/Trivy,
  dédoublonne, crée un `Job` par alerte. RBAC : `create` sur `Jobs` uniquement.
  Expose aussi `/metrics` (scrapé par `k8s/servicemonitor.yaml`) et un endpoint
  interne `/internal/job-metrics` où les Jobs éphémères reportent leur résultat.
- `src/job_runner/` — code exécuté par chaque `Job` éphémère :
  - `enrichment.py` : lecture seule du manifeste K8s concerné (résolution ns/name/kind
    propre à chaque source) + construction du prompt.
  - `ai_client.py` : appel `POST {OVH_AI_ENDPOINTS_BASE_URL}/chat/completions` (`https://oai.endpoints.kepler.ai.cloud.ovh.net/v1` par défaut, compatible OpenAI)
    avec `Authorization: Bearer $OVH_AI_ENDPOINTS_ACCESS_TOKEN`.
  - `validation.py` : valide le manifeste avec `kubeconform -strict` (100% local,
    aucun accès cluster) avant tout commit — un manifeste invalide fait échouer
    le Job, aucune PR n'est ouverte.
  - `pr_generator.py` : vérifie d'abord qu'une PR ouverte n'existe pas déjà pour ce
    fingerprint (idempotence sur retry), sinon clone, écrase le fichier GitOps
    existant de la cible (whitelist `KNOWN_REMEDIATION_TARGETS`), commit sur une
    branche `ai-remediation/*`, ouvre une PR **draft**.
  - `metrics.py` : reporting best-effort du résultat du Job au webhook (le Job
    lui-même ne peut pas être scrapé, trop éphémère).
  - `main.py` : orchestration des étapes ci-dessus.
- `k8s/networkpolicy.yaml` — seuls `falco`, `trivy-system` (alertes) et `monitoring`
  (scrape `/metrics`) peuvent atteindre le webhook.
- `tests/` — suite `pytest` (29 tests, aucun accès réseau/cluster requis) : `pytest`
  depuis ce dossier (`ai-remediation-engine/`), voir `pytest.ini`/`requirements-dev.txt`.

## Secrets requis (non versionnés)

| Secret | Namespace | Clé | Usage |
|---|---|---|---|
| `ai-endpoints-credentials` | `remediation` | `token` | Bearer token AI Endpoints, monté uniquement dans les Jobs |
| `git-pr-credentials` | `remediation` | `token` | Token Git scopé `pull-requests: write` uniquement, monté uniquement dans les Jobs |
| `webhook-shared-token` | `remediation` | `token` | Optionnel (durcissement) — active l'authentification `X-Webhook-Token` sur `/webhook/*`. Sans ce secret, le webhook démarre quand même et logue un avertissement. |

Voir `k8s/secrets.example.yaml` pour le format (à créer réellement via
`kubectl create secret` ou un gestionnaire de secrets externe — jamais en clair dans Git).

Pour activer réellement `webhook-shared-token`, câbler la même valeur côté
émetteurs (hors GitOps, pour ne jamais committer ce secret dans une
`Application`) : voir les commandes `kubectl set env` commentées dans
`k8s/secrets.example.yaml`.

## Pourquoi un Job par alerte plutôt qu'un process persistant ?

- **Isolation** : le Bearer token AI Endpoints et le token Git ne vivent que le temps du traitement d'une alerte.
- **Auditabilité** : chaque remédiation est un Job nommé, avec ses propres logs et son propre statut.
- **Résilience** : `backoffLimit`/retries natifs K8s, pas de logique de retry à réimplémenter.
- **Least privilege** : le webhook (toujours actif, donc plus exposé) n'a jamais les credentials sensibles ; seul le Job, éphémère, les détient.
