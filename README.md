# Hackathon OVHcloud x Ynov — Équipe 6

Chaîne d'audit et de remédiation GitOps sécurisée sur Managed Kubernetes OVHcloud.

Stack : Argo CD · Trivy Operator · Falco · Kyverno · Prometheus · OVHcloud AI Endpoints.

## Arborescence

```
.
├── infra/                     # Outils CNCF (gérés par Argo CD, app-of-apps)
│   ├── argocd/
│   │   ├── projects/          # AppProject (RBAC Argo CD)
│   │   └── applications/      # Application CRs (1 par outil)
│   ├── kyverno/policies/      # ClusterPolicy (policy-as-code)
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
│   │   └── job_runner/            # Job éphémère : enrichissement/IA/PR/metrics
│   ├── k8s/                   # RBAC, Deployment, ServiceMonitor
│   └── Dockerfile
└── docs/
    ├── architecture.md        # Diagramme de séquence (Mermaid)
    └── DOSSIER_TECHNIQUE.md   # Choix d'outils (+ tableau statut CNCF), incidents, preuves
```

Voir `docs/architecture.md` pour le cycle de vie complet d'une faille (détection → PR → merge humain → sync Argo CD), et `docs/DOSSIER_TECHNIQUE.md` §2.0 pour le tableau récapitulatif du statut CNCF de chaque outil.
