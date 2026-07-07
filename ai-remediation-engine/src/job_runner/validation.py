"""
Validation structurelle du manifeste généré par l'IA, AVANT ouverture de PR.

Utilise `kubeconform` (schémas Kubernetes officiels) en local, sur le fichier
YAML uniquement — aucun accès au cluster, donc aucun besoin d'étendre le
RBAC du Job. C'est un point important : `kubectl apply --dry-run=server`
aurait été plus simple, mais Kubernetes exige le verbe d'écriture réel
(`create`/`update`) même en dry-run — ça aurait cassé l'invariant central du
projet ("le Job n'a jamais de droit d'écriture sur le cluster").

Une PR ouverte avec un YAML structurellement invalide (mauvais type, champ
requis manquant) décrédibiliserait toute la démo : on préfère faire échouer
le Job (donc aucune PR) plutôt que de laisser passer un manifeste cassé.
"""
import logging
import subprocess
import tempfile
from pathlib import Path

log = logging.getLogger("remediation-job.validation")


class ValidationError(Exception):
    pass


def validate_manifest(yaml_text: str, kind: str) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(yaml_text)
        path = Path(f.name)

    try:
        result = subprocess.run(
            ["kubeconform", "-strict", "-summary", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise ValidationError(
                f"Manifeste {kind} rejeté par kubeconform (code {result.returncode}):\n"
                f"{result.stdout}\n{result.stderr}"
            )
        log.info("Manifeste %s validé par kubeconform.", kind)
    finally:
        path.unlink(missing_ok=True)
