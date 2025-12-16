from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import shutil
import os
import json

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"status": "Cloud Sentinel is Ready (REAL MODE) 🚀"}

@app.post("/scan-code")
async def scan_code(file: UploadFile = File(...)):
    # 1. Sauvegarde temporaire du fichier
    file_path = f"/tmp/{file.filename}"
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 2. VRAI SCAN : Lancement de Checkov
    # On capture la sortie en JSON pour l'afficher proprement
    try:
        cmd = ["checkov", "-f", file_path, "--output", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Checkov renvoie souvent des erreurs de format, on gère ça :
        try:
            output_json = json.loads(result.stdout)
        except:
            output_json = {"raw_output": result.stdout}
            
    except Exception as e:
        output_json = {"error": str(e)}

    # Nettoyage
    if os.path.exists(file_path):
        os.remove(file_path)

    return output_json

@app.post("/scan-cloud")
async def scan_cloud():
    # VRAI SCAN : Lancement de Prowler (Mode Light pour aller vite)
    # Attention : Prowler prend du temps (2-3 minutes)
    try:
        # On lance juste un check simple S3 pour la démo (sinon c'est trop long)
        cmd = ["prowler", "aws", "--services", "s3", "--ignore-exit-code-3"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        # On renvoie le texte brut car Prowler génère des couleurs difficiles à parser en JSON simple
        return {"status": "Real Scan executed", "output": result.stdout}
    except Exception as e:
        return {"error": str(e)}