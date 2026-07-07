# Architecture — Boucle de Remédiation GitOps Sécurisée

```mermaid
sequenceDiagram
    autonumber
    participant WL as Workload (cluster)
    participant Falco
    participant Trivy as Trivy Operator
    participant Sidekick as Falcosidekick
    participant WH as Webhook Receiver (Deployment)
    participant Job as K8s Job (Enrichment + IA)
    participant AI as OVHcloud AI Endpoints
    participant Git as Dépôt GitOps (Git Provider)
    participant Human as Revue Humaine
    participant Argo as Argo CD

    Note over Falco,Trivy: Détection continue
    WL->>Falco: Syscall suspect (runtime)
    WL->>Trivy: Scan image/config (périodique)

    Falco->>Sidekick: Alerte runtime (JSON)
    Trivy->>WH: VulnerabilityReport CR (watch/webhook)
    Sidekick->>WH: POST alerte enrichie

    WH->>WH: Validation + dédoublonnage
    WH->>Job: Création Job (1 alerte = 1 Job)

    activate Job
    Job->>Job: Enrichissement (contexte K8s, manifeste, CVE, règle Falco)
    Job->>AI: POST /chat/completions (Bearer token)
    AI-->>Job: Manifeste corrigé complet (YAML) + explication
    Job->>Job: Validation structurelle (kubeconform, 100% local, 0 accès cluster)
    alt Manifeste invalide
        Job->>Job: Job en échec — aucune PR ouverte
    else Manifeste valide
        Job->>Git: Écrase le fichier existant (cible whitelistée) + commit
        Job->>Git: Ouverture Pull Request (draft)
    end
    deactivate Job

    Git-->>Human: Notification PR à valider
    Note over Human: Aucune fusion automatique.<br/>Revue obligatoire du diff.
    Human->>Git: Approve + Merge manuel

    Git->>Argo: Webhook / poll (repo modifié)
    Argo->>Argo: Diff détecté
    Argo->>WL: Sync (apply correctif)
    Argo-->>Human: Statut sync (Healthy/Synced)
```

## Invariants de sécurité

- Le `Job` d'enrichissement IA n'a **aucun droit d'écriture** sur le cluster (RBAC `get`/`list` seulement).
- Le token GitHub/GitLab utilisé par le `Job` n'a **jamais** le droit de merge (scope `pull_request:write` seulement, pas `contents:write` sur la branche protégée).
- Seul Argo CD (déjà autorisé, GitOps) applique les changements sur le cluster, et seulement après merge humain.
- Toute policy Kyverno générée par l'IA est livrée en mode proposé dans la PR — jamais appliquée en `Enforce` sans revue.
