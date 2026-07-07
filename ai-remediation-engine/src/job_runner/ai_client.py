"""
Client OVHcloud AI Endpoints.

Authentification : Bearer token (clé d'accès AI Endpoints), fourni au Job
via le Secret `ai-endpoints-credentials` (jamais en clair dans le repo,
jamais détenu par le webhook receiver).
"""
import logging
import os
import time

import httpx

log = logging.getLogger("remediation-job.ai-client")

AI_ENDPOINTS_BASE_URL = os.environ.get(
    "OVH_AI_ENDPOINTS_BASE_URL", "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1"
)
AI_ENDPOINTS_MODEL = os.environ.get("OVH_AI_ENDPOINTS_MODEL", "Meta-Llama-3_3-70B-Instruct")


class AIEndpointsClient:
    def __init__(self, token: str | None = None, base_url: str = AI_ENDPOINTS_BASE_URL):
        self.token = token or os.environ["OVH_AI_ENDPOINTS_ACCESS_TOKEN"]
        self.base_url = base_url.rstrip("/")

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def generate_remediation(
        self,
        prompt: str,
        model: str = AI_ENDPOINTS_MODEL,
        max_retries: int = 3,
        backoff_seconds: float = 2.0,
        transport: httpx.BaseTransport | None = None,
    ) -> str:
        """`transport` n'est là que pour les tests (httpx.MockTransport) — en
        production, None laisse httpx utiliser le transport réseau réel."""
        url = f"{self.base_url}/chat/completions"
        body = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Tu es un moteur de remédiation Kubernetes. Tu réponds "
                        "uniquement avec du YAML et une explication courte, jamais "
                        "de commande à exécuter directement sur un cluster."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 1500,
        }

        last_exc: httpx.HTTPStatusError | None = None
        with httpx.Client(timeout=60, transport=transport) as http:
            for attempt in range(max_retries):
                resp = http.post(url, headers=self._headers(), json=body)
                try:
                    resp.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    retryable = resp.status_code == 429 or resp.status_code >= 500
                    if not retryable or attempt == max_retries - 1:
                        raise
                    last_exc = exc
                    wait = backoff_seconds * (2**attempt)
                    log.warning(
                        "Appel AI Endpoints échoué (HTTP %d), retry %d/%d dans %.1fs",
                        resp.status_code,
                        attempt + 1,
                        max_retries,
                        wait,
                    )
                    time.sleep(wait)
                    continue
                return resp.json()["choices"][0]["message"]["content"]

        raise last_exc  # pragma: no cover — inatteignable (la boucle raise ou return toujours)
