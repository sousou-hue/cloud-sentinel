FROM python:3.9-slim

WORKDIR /app

# Installation des outils système (Git est requis pour Prowler)
RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*

# Installation des libs Python et des outils de sécurité
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]