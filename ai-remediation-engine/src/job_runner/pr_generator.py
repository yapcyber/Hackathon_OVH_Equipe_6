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
from pathlib import Path

import httpx

GIT_REPO_URL = os.environ["GITOPS_REPO_URL"]  # ex: https://github.com/yapcyber/Hackathon_OVH_Equipe_6.git
GIT_PR_TOKEN = os.environ["GIT_PR_TOKEN"]
GITHUB_API_URL = os.environ.get("GITHUB_API_URL", "https://api.github.com")
GITHUB_REPO_SLUG = os.environ["GITHUB_REPO_SLUG"]  # ex: yapcyber/Hackathon_OVH_Equipe_6

# Cibles de remédiation connues et autorisées (namespace, name) -> chemin du
# manifeste dans le dépôt GitOps. Volontairement une whitelist explicite :
# le namespace/name viennent d'un payload Falco/Trivy non maîtrisé, on ne
# construit jamais un chemin de fichier directement à partir de ces valeurs
# (pas de traversée de chemin possible, pas d'écriture hors périmètre connu).
# Le fichier ciblé doit déjà être listé dans le kustomization.yaml de l'app :
# on écrase un fichier existant suivi par Argo CD, jamais un fichier orphelin.
KNOWN_REMEDIATION_TARGETS = {
    ("demo", "vulnerable-demo"): "apps/vulnerable-demo/deployment.yaml",
}


def _find_existing_pr(branch: str) -> str | None:
    """Idempotence : un retry K8s (backoffLimit) sur la même alerte réutilise
    le même fingerprint donc la même branche. Si une PR ouverte existe déjà
    pour cette branche, on la retourne au lieu d'en ouvrir une deuxième."""
    owner = GITHUB_REPO_SLUG.split("/")[0]
    resp = httpx.get(
        f"{GITHUB_API_URL}/repos/{GITHUB_REPO_SLUG}/pulls",
        headers={
            "Authorization": f"Bearer {GIT_PR_TOKEN}",
            "Accept": "application/vnd.github+json",
        },
        params={"head": f"{owner}:{branch}", "state": "open"},
        timeout=30,
    )
    resp.raise_for_status()
    results = resp.json()
    return results[0]["html_url"] if results else None


def open_remediation_pr(
    alert_source: str,
    fingerprint: str,
    namespace: str,
    name: str,
    patch_yaml: str,
    explanation: str,
) -> str:
    target_rel_path = KNOWN_REMEDIATION_TARGETS.get((namespace, name))
    if target_rel_path is None:
        raise ValueError(
            f"Cible de remédiation inconnue ({namespace}/{name}) — PR non ouverte. "
            "Ajouter l'entrée à KNOWN_REMEDIATION_TARGETS si cette cible est légitime."
        )

    branch = f"ai-remediation/{alert_source}-{fingerprint}"

    existing_pr = _find_existing_pr(branch)
    if existing_pr:
        return existing_pr

    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = Path(tmp) / "repo"
        authed_url = GIT_REPO_URL.replace("https://", f"https://x-access-token:{GIT_PR_TOKEN}@")

        subprocess.run(["git", "clone", "--depth", "1", authed_url, str(repo_dir)], check=True)
        subprocess.run(["git", "-C", str(repo_dir), "checkout", "-b", branch], check=True)

        target_path = repo_dir / target_rel_path
        if not target_path.is_file():
            raise ValueError(f"Fichier cible attendu introuvable dans le repo: {target_rel_path}")
        target_path.write_text(patch_yaml)

        subprocess.run(["git", "-C", str(repo_dir), "add", str(target_path)], check=True)
        subprocess.run(
            ["git", "-C", str(repo_dir), "-c", "user.email=ai-remediation-bot@equipe6.local",
             "-c", "user.name=ai-remediation-bot", "commit", "-m",
             f"fix({alert_source}): correctif proposé par IA pour {fingerprint}"],
            check=True,
        )
        # --force : cette branche est exclusivement créée/possédée par ce bot
        # (préfixe ai-remediation/*, jamais touchée par un humain) — un retry
        # sur la même alerte doit pouvoir écraser une tentative précédente
        # avortée avant l'ouverture de la PR (sinon le push échoue en
        # non-fast-forward et le Job reste bloqué en échec indéfiniment).
        subprocess.run(["git", "-C", str(repo_dir), "push", "--force", "origin", branch], check=True)

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
