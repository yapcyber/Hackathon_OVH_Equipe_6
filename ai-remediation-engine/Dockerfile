FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

# Image unique pour les deux rôles : Deployment (webhook_receiver) et Job (job_runner.main).
# Le rôle exécuté est déterminé par la commande du conteneur (voir k8s/*.yaml), pas par le build.
ENTRYPOINT ["python"]
CMD ["-m", "uvicorn", "webhook_receiver:app", "--host", "0.0.0.0", "--port", "8080"]
