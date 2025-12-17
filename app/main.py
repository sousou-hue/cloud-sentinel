from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import shutil
import os
import boto3
import uuid
from datetime import datetime

app = FastAPI()

# Connexion à DynamoDB (grâce au Rôle IAM de l'infra)
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
table = dynamodb.Table('SentinelHistory')

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"status": "Cloud Sentinel PRO is Ready 🛡️"}

@app.post("/scan-code")
async def scan_code(file: UploadFile = File(...)):
    scan_id = str(uuid.uuid4())
    file_path = f"/tmp/{file.filename}"
    
    # 1. Sauvegarde du fichier
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 2. VRAI SCAN CHECKOV
    try:
        # On lance checkov et on récupère juste le résumé simple pour l'instant
        cmd = ["checkov", "-f", file_path, "--compact"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout
        status = "Success"
    except Exception as e:
        output = str(e)
        status = "Error"

    # 3. Sauvegarde dans DynamoDB
    table.put_item(Item={
        'scan_id': scan_id,
        'date': str(datetime.now()),
        'type': 'SAST (Code)',
        'status': status,
        'details': output[:500] # On garde juste le début pour pas surcharger la DB gratuite
    })

    if os.path.exists(file_path):
        os.remove(file_path)

    return {"scan_id": scan_id, "report": output}

@app.post("/scan-cloud")
async def scan_cloud():
    scan_id = str(uuid.uuid4())
    
    # 2. VRAI SCAN PROWLER (Mode rapide : juste IAM)
    # On ne scanne que IAM pour que ça prenne 10s et pas 10min pour la démo
    try:
        cmd = ["prowler", "aws", "--services", "iam", "--ignore-exit-code-3"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout
        status = "Success"
    except Exception as e:
        output = str(e)
        status = "Error"

    # 3. Sauvegarde dans DynamoDB
    table.put_item(Item={
        'scan_id': scan_id,
        'date': str(datetime.now()),
        'type': 'CSPM (Cloud)',
        'status': status,
        'details': output[:500]
    })

    return {"scan_id": scan_id, "report": output}