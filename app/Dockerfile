FROM python:3.9-slim

WORKDIR /app

# 1. Outils système
RUN apt-get update && \
    apt-get install -y git curl unzip && \
    rm -rf /var/lib/apt/lists/*

# 2. Mise à jour de PIP
RUN pip install --upgrade pip

# 3. Installation des librairies de l'APP (Rapide)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Installation de CHECKOV (Isolé)
# On l'installe tout seul pour qu'il gère ses dépendances sans conflit
RUN pip install --no-cache-dir checkov

# 5. Installation de PROWLER (Isolé)
RUN pip install --no-cache-dir prowler

COPY main.py .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]