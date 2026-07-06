"""
Client OVHcloud AI Endpoints.

Authentification : Bearer token (clé d'accès AI Endpoints), fourni au Job
via le Secret `ai-endpoints-credentials` (jamais en clair dans le repo,
jamais détenu par le webhook receiver).
"""
import os

import httpx

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

    def generate_remediation(self, prompt: str, model: str = AI_ENDPOINTS_MODEL) -> str:
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

        with httpx.Client(timeout=60) as http:
            resp = http.post(url, headers=self._headers(), json=body)
            resp.raise_for_status()
            data = resp.json()

        return data["choices"][0]["message"]["content"]
