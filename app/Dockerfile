FROM python:3.6

WORKDIR /app

# 1. Installation des outils système + PIPX
# PIPX sert à installer des outils Python dans des bulles isolées
RUN apt-get update && \
    apt-get install -y git curl unzip && \
    pip install --no-cache-dir pipx && \
    rm -rf /var/lib/apt/lists/*

# On ajoute le dossier des outils installés par pipx au PATH
ENV PATH="/root/.local/bin:${PATH}"

# 2. Installation de CHECKOV via pipx (Isolé)
# Il aura ses propres dépendances, il n'embêtera personne
RUN pipx install checkov

# 3. Installation de PROWLER via pipx (Isolé)
RUN pipx install prowler

# 4. Installation des dépendances de l'APP (Global)
# Celles-ci sont pour ton code main.py
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copie du code
COPY main.py .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]