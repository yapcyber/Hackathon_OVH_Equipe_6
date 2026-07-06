FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

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
