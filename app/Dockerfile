FROM python:3.9-slim

WORKDIR /app

# Installation des outils système nécessaires pour Prowler et Checkov
RUN apt-get update && apt-get install -y \
    git \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Installation des dépendances Python
COPY requirements.txt .
# On ajoute checkov et prowler aux librairies
RUN pip install --no-cache-dir -r requirements.txt checkov prowler

COPY main.py .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]