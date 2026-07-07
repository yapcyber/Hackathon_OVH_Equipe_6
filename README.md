# Hackathon OVHcloud x Ynov — Équipe 6

Chaîne d'audit et de remédiation GitOps sécurisée sur Managed Kubernetes OVHcloud.

Stack : Argo CD · Trivy Operator · Falco · Kyverno · Prometheus · OVHcloud AI Endpoints.

## Arborescence

```
.
├── .github/workflows/ci.yml   # Tests + validation manifestes + build/push image
├── infra/                     # Outils CNCF (gérés par Argo CD, app-of-apps)
│   ├── argocd/
│   │   ├── projects/          # AppProject (RBAC Argo CD, destinations resserrées)
│   │   └── applications/      # Application CRs (1 par outil)
│   ├── kyverno/policies/      # 5 ClusterPolicy (1 Enforce, 4 Audit) — policy-as-code
│   ├── falco/                 # values Falco + Falcosidekick
│   ├── trivy/                 # values Trivy Operator
│   └── prometheus/
│       ├── values.yaml        # values kube-prometheus-stack (référence)
│       └── dashboards/        # ConfigMaps Grafana (dashboard custom moteur IA)
├── apps/
│   └── vulnerable-demo/       # Workload volontairement vulnérable (démo)
├── ai-remediation-engine/     # Moteur IA : webhook + Job d'enrichissement/PR
│   ├── src/
│   │   ├── webhook_receiver.py    # Deployment : ingestion + métriques /metrics
│   │   └── job_runner/            # Job éphémère : enrichissement/validation/IA/PR/metrics
│   ├── k8s/                   # RBAC, Deployment (probes), ServiceMonitor, NetworkPolicy
│   ├── tests/                 # pytest (29 tests, aucun accès réseau/cluster)
│   └── Dockerfile             # inclut kubeconform (validation locale des manifestes)
└── docs/
    ├── architecture.md        # Diagramme de séquence (Mermaid)
    └── DOSSIER_TECHNIQUE.md   # Choix d'outils (+ tableau statut CNCF), incidents, preuves, CI
```

Voir `docs/architecture.md` pour le cycle de vie complet d'une faille (détection → PR → merge humain → sync Argo CD), et `docs/DOSSIER_TECHNIQUE.md` §2.0 pour le tableau récapitulatif du statut CNCF de chaque outil.
