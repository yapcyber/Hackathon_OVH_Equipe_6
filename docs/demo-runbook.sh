#!/usr/bin/env bash
# Runbook de démo — Hackathon OVHcloud x Ynov, Équipe 6
#
# Usage : bash docs/demo-runbook.sh
# Chaque étape s'arrête et attend une touche (Entrée) avant de continuer,
# pour que tu puisses parler dessus devant le jury. Ctrl+C à tout moment
# pour sortir proprement.
#
# Pré-requis à faire AVANT la démo (une seule fois) :
#   1. export KUBECONFIG=/home/yanis/HACKATHON/kubeconfig-equipe-6.yaml
#   2. Si tu veux rejouer la Phase 6 (PR IA) : régénère un token GitHub
#      fine-grained (Contents: write + Pull requests: write, scopé au repo
#      yapcyber/Hackathon_OVH_Equipe_6) et mets-le à jour :
#        kubectl -n remediation create secret generic git-pr-credentials \
#          --from-literal=token="<NOUVEAU_TOKEN>" \
#          --dry-run=client -o yaml | kubectl apply -f -
#      (le précédent a été révoqué après le test de la veille)

set -uo pipefail

KUBECONFIG="${KUBECONFIG:-/home/yanis/HACKATHON/kubeconfig-equipe-6.yaml}"
export KUBECONFIG

pause() {
  echo
  read -rp "   ▶ [Entrée pour continuer] " _
  echo
}

banner() {
  echo
  echo "════════════════════════════════════════════════════════════════"
  echo "  $1"
  echo "════════════════════════════════════════════════════════════════"
}

# ────────────────────────────────────────────────────────────────────
banner "PHASE 0 — Contexte : cluster Managed Kubernetes OVHcloud + GitOps"
# ────────────────────────────────────────────────────────────────────
echo "Cluster : 3 nodes, géré à 100% via Argo CD depuis le repo GitHub"
echo "yapcyber/Hackathon_OVH_Equipe_6."
echo
kubectl get nodes
pause

echo "Toute la stack CNCF (Argo CD, Kyverno, Trivy, Falco, Prometheus,"
echo "moteur IA) est déclarée en Git et synchronisée automatiquement :"
echo
kubectl -n argocd get applications
pause


# ────────────────────────────────────────────────────────────────────
banner "PHASE 1 — Kyverno : policy-as-code, admission bloquée en direct"
# ────────────────────────────────────────────────────────────────────
echo "La ClusterPolicy 'disallow-privileged-containers' est active en mode"
echo "Enforce sur tout le cluster :"
echo
kubectl get clusterpolicy disallow-privileged-containers
pause

echo "Tentative de création d'un pod privilégié (comme le ferait un"
echo "attaquant ou une config malveillante) :"
echo
kubectl run demo-privileged --image=nginx:latest --restart=Never -n demo \
  --overrides='{"spec":{"containers":[{"name":"demo-privileged","image":"nginx:latest","securityContext":{"privileged":true}}]}}' \
  || echo
echo
echo ">>> Bloqué à l'admission, AVANT même d'atteindre un node. <<<"
pause


# ────────────────────────────────────────────────────────────────────
banner "PHASE 2 — Trivy Operator : audit de sécurité continu"
# ────────────────────────────────────────────────────────────────────
echo "Le workload de démo (vulnerable-demo) tourne avec une image taguée"
echo "'latest' et un utilisateur root — Trivy le scanne en continu :"
echo
kubectl -n demo get deployment vulnerable-demo -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
kubectl -n demo get vulnerabilityreports 2>/dev/null
kubectl -n demo get configauditreports 2>/dev/null
pause

echo "Détail des vulnérabilités détectées (résumé) :"
kubectl -n demo get vulnerabilityreports -o json 2>/dev/null | \
  python3 -c "
import json,sys
d = json.load(sys.stdin)
for r in d.get('items', []):
    s = r.get('report', {}).get('summary', {})
    print(r['metadata']['name'], '->', s)
" || echo "(aucun rapport pour le moment, le scan périodique n'est peut-être pas encore passé)"
pause


# ────────────────────────────────────────────────────────────────────
banner "PHASE 3 — Falco : détection runtime en direct"
# ────────────────────────────────────────────────────────────────────
echo "On ouvre un shell interactif DANS le conteneur vulnérable — c'est"
echo "exactement le genre de comportement qu'un attaquant ferait après"
echo "une compromission :"
echo
POD=$(kubectl -n demo get pods -l app=vulnerable-demo -o jsonpath='{.items[0].metadata.name}')
echo "Pod ciblé : $POD"
pause

echo "(Ouverture du shell — tape 'exit' pour en sortir et continuer la démo)"
kubectl -n demo exec -it "$POD" -- sh -c "echo 'Shell ouvert dans le conteneur — regarde les logs Falco maintenant'; sh" || true
pause

echo "Alerte Falco correspondante (règle 'Terminal shell in container') :"
echo
kubectl -n falco logs -l app.kubernetes.io/name=falco --tail=200 2>/dev/null | grep -i "terminal shell" | tail -5
pause


# ────────────────────────────────────────────────────────────────────
banner "PHASE 4 — Prometheus / Grafana : observabilité"
# ────────────────────────────────────────────────────────────────────
echo "Prometheus scrape Kyverno, Falco, Trivy Operator et le cluster :"
echo
kubectl -n monitoring get pods
echo
echo "Pour ouvrir Grafana en local (identifiants par défaut: admin / prom-operator) :"
echo "  kubectl -n monitoring port-forward svc/prometheus-grafana 3000:80"
echo "  puis http://localhost:3000"
pause


# ────────────────────────────────────────────────────────────────────
banner "PHASE 5 — Le moteur IA : de l'alerte à la Pull Request"
# ────────────────────────────────────────────────────────────────────
echo "On simule une alerte réelle (namespace 'demo', payload Falco) envoyée"
echo "au webhook de remédiation :"
echo
kubectl -n remediation port-forward svc/ai-remediation-webhook 8080:8080 >/tmp/demo-pf.log 2>&1 &
PF_PID=$!
sleep 2
TS=$(date +%s 2>/dev/null || echo "manual")
curl -s -X POST http://localhost:8080/webhook/falco \
  -H "Content-Type: application/json" \
  -d "{
    \"rule\": \"Terminal shell in container (demo-live-${TS})\",
    \"priority\": \"Warning\",
    \"output\": \"A shell was spawned in a container with an attached terminal\",
    \"output_fields\": {
      \"k8s.ns.name\": \"demo\",
      \"k8s.pod.name\": \"${POD}\",
      \"container.image.repository\": \"nginx\",
      \"container.image.tag\": \"latest\"
    }
  }"
echo
kill "$PF_PID" 2>/dev/null
pause

echo "Un Job Kubernetes éphémère a été créé pour traiter CETTE alerte :"
echo
kubectl -n remediation get jobs --sort-by=.metadata.creationTimestamp | tail -5
pause

echo "On suit son exécution (enrichissement -> appel AI Endpoints -> PR) :"
echo "(rejoue cette ligne si le job n'est pas encore 'Complete')"
LATEST_JOB=$(kubectl -n remediation get jobs -o jsonpath='{.items[-1:].metadata.name}')
kubectl -n remediation logs "job/$LATEST_JOB" --all-containers --follow --tail=100 || true
pause

echo "Si le token PR est valide, la Pull Request est visible ici :"
echo "  https://github.com/yapcyber/Hackathon_OVH_Equipe_6/pulls"
echo
echo ">>> Point clé pour le jury : la PR est en DRAFT. AUCUNE action <<<"
echo ">>> n'a touché le cluster au-delà de cette ouverture de PR.     <<<"
echo ">>> C'est toi qui review et merge à la main.                   <<<"
pause


# ────────────────────────────────────────────────────────────────────
banner "PHASE 6 — Boucle GitOps : merge humain -> resync Argo CD"
# ────────────────────────────────────────────────────────────────────
echo "Workflow à montrer (pas besoin de l'exécuter en live si pas de PR ouverte) :"
echo "  1. Revue du diff proposé par l'IA sur GitHub"
echo "  2. Merge manuel (toi, humain) après validation"
echo "  3. Argo CD détecte le changement et resynchronise automatiquement :"
echo
kubectl -n argocd get applications
echo
echo "════════════════════════════════════════════════════════════════"
echo "  FIN DE LA DÉMO"
echo "════════════════════════════════════════════════════════════════"
