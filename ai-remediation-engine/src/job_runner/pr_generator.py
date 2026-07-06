"""
Génération de la Pull Request — dernière étape de l'automatisation.

IMPORTANT : ce module n'effectue JAMAIS de merge. Il ouvre une PR en mode
draft sur le dépôt GitOps et s'arrête. Le token utilisé (GIT_PR_TOKEN) doit
être scopé côté fournisseur Git à la seule permission "pull-requests: write"
(pas "contents: write" sur la branche protégée `main`, pas de droit d'admin).
"""
import os
import subprocess
import tempfile
import time
from pathlib import Path

import httpx

GIT_REPO_URL = os.environ["GITOPS_REPO_URL"]  # ex: https://github.com/yapcyber/Hackathon_OVH_Equipe_6.git
GIT_PR_TOKEN = os.environ["GIT_PR_TOKEN"]
GITHUB_API_URL = os.environ.get("GITHUB_API_URL", "https://api.github.com")
GITHUB_REPO_SLUG = os.environ["GITHUB_REPO_SLUG"]  # ex: yapcyber/Hackathon_OVH_Equipe_6


def open_remediation_pr(alert_source: str, fingerprint: str, patch_yaml: str, explanation: str) -> str:
    branch = f"ai-remediation/{alert_source}-{fingerprint}"

    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = Path(tmp) / "repo"
        authed_url = GIT_REPO_URL.replace("https://", f"https://x-access-token:{GIT_PR_TOKEN}@")

        subprocess.run(["git", "clone", "--depth", "1", authed_url, str(repo_dir)], check=True)
        subprocess.run(["git", "-C", str(repo_dir), "checkout", "-b", branch], check=True)

        patch_path = repo_dir / "apps" / "vulnerable-demo" / f"ai-fix-{fingerprint}.yaml"
        patch_path.write_text(patch_yaml)

        subprocess.run(["git", "-C", str(repo_dir), "add", str(patch_path)], check=True)
        subprocess.run(
            ["git", "-C", str(repo_dir), "-c", "user.email=ai-remediation-bot@equipe6.local",
             "-c", "user.name=ai-remediation-bot", "commit", "-m",
             f"fix({alert_source}): correctif proposé par IA pour {fingerprint}"],
            check=True,
        )
        subprocess.run(["git", "-C", str(repo_dir), "push", "origin", branch], check=True)

    pr_body = (
        f"### Correctif généré automatiquement (source: `{alert_source}`)\n\n"
        f"{explanation}\n\n"
        "**Ce correctif n'a pas été appliqué automatiquement.** "
        "Merge manuel requis après revue humaine.\n"
    )

    resp = httpx.post(
        f"{GITHUB_API_URL}/repos/{GITHUB_REPO_SLUG}/pulls",
        headers={
            "Authorization": f"Bearer {GIT_PR_TOKEN}",
            "Accept": "application/vnd.github+json",
        },
        json={
            "title": f"[AI] Remédiation {alert_source} — {fingerprint}",
            "head": branch,
            "base": "main",
            "body": pr_body,
            "draft": True,  # jamais mergeable en un clic sans revue explicite
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["html_url"]
