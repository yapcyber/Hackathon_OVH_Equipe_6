FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git curl && rm -rf /var/lib/apt/lists/*

# kubeconform : validation structurelle (schémas K8s) du manifeste généré par
# l'IA, AVANT ouverture de PR (job_runner/validation.py) — en local, sans
# toucher au cluster, pour ne jamais avoir besoin d'étendre le RBAC
# read-only du Job avec un verbe d'écriture (même en dry-run).
ARG KUBECONFORM_VERSION=0.8.0
ARG KUBECONFORM_SHA256=9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883
RUN curl -sSL -o /tmp/kubeconform.tar.gz \
      "https://github.com/yannh/kubeconform/releases/download/v${KUBECONFORM_VERSION}/kubeconform-linux-amd64.tar.gz" \
    && echo "${KUBECONFORM_SHA256}  /tmp/kubeconform.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/kubeconform.tar.gz -C /usr/local/bin kubeconform \
    && rm /tmp/kubeconform.tar.gz

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

# Image unique pour les deux rôles : Deployment (webhook_receiver) et Job (job_runner.main).
# Le rôle exécuté est déterminé par la commande du conteneur (voir k8s/*.yaml), pas par le build.
RUN useradd --uid 1000 --create-home appuser
USER 1000

ENTRYPOINT ["python"]
CMD ["-m", "uvicorn", "webhook_receiver:app", "--host", "0.0.0.0", "--port", "8080"]
