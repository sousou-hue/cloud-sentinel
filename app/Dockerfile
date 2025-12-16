# On part d'une version légère de Python
FROM python:3.9-slim

# On prépare le dossier de travail
WORKDIR /app

# On installe les outils
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# On copie le code
COPY main.py .

# On lance l'application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]