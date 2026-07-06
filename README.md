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
│   └── prometheus/            # values kube-prometheus-stack
├── apps/
│   └── vulnerable-demo/       # Workload volontairement vulnérable (démo)
├── ai-remediation-engine/     # Moteur IA : webhook + Job d'enrichissement/PR
│   ├── src/
│   ├── k8s/
│   └── Dockerfile
└── docs/
    └── architecture.md        # Diagramme de séquence (Mermaid)
```

Voir `docs/architecture.md` pour le cycle de vie complet d'une faille (détection → PR → merge humain → sync Argo CD).
