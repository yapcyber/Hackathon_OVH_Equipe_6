"""
Variables d'environnement requises par les modules au moment de l'import
(webhook_receiver.py, pr_generator.py) — exécuté par pytest AVANT la
collecte des tests, donc avant tout `import job_runner...` / `import
webhook_receiver`. Valeurs factices : aucun de ces tests ne touche le réseau
ou un vrai cluster.
"""
import os

os.environ.setdefault("JOB_IMAGE", "test-image:dev")
os.environ.setdefault("GITOPS_REPO_URL", "https://github.com/example/example.git")
os.environ.setdefault("GIT_PR_TOKEN", "test-token")
os.environ.setdefault("GITHUB_REPO_SLUG", "example/example")
os.environ.setdefault("OVH_AI_ENDPOINTS_ACCESS_TOKEN", "test-token")
