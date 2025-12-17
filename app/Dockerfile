FROM python:3.9-slim

WORKDIR /app

# 1. Installation des outils système (Git est OBLIGATOIRE pour Prowler)
RUN apt-get update && \
    apt-get install -y git curl unzip && \
    rm -rf /var/lib/apt/lists/*

# 2. Mise à jour de PIP (Crucial pour éviter les blocages)
RUN pip install --upgrade pip

# 3. Installation des dépendances
COPY requirements.txt .

# On installe avec --no-cache-dir pour alléger l'image
# On augmente le timeout pour éviter que ça plante si le réseau est lent
RUN pip install --no-cache-dir --default-timeout=100 -r requirements.txt

# 4. Copie du code
COPY main.py .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]