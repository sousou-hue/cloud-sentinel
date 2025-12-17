from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import shutil
import os
import boto3
import uuid
import json
import re
from datetime import datetime

app = FastAPI(

# Connexion DynamoDB
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
table = dynamodb.Table('SentinelHistory')

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Fonction pour nettoyer les codes couleurs du terminal (les \u001b...)
def clean_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

@app.get("/")
def read_root():
    return {"status": "Cloud Sentinel PRO is Ready 🛡️"}

# --- NOUVELLE FONCTIONNALITÉ : HISTORIQUE ---
@app.get("/history")
def get_history():
    try:
        # On récupère tout l'historique
        response = table.scan()
        items = response.get('Items', [])
        # On trie du plus récent au plus vieux
        items.sort(key=lambda x: x['date'], reverse=True)
        return items
    except Exception as e:
        return [{"error": str(e)}]

@app.post("/scan-code")
async def scan_code(file: UploadFile = File(...)):
    scan_id = str(uuid.uuid4())
    file_path = f"/tmp/{file.filename}"
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        # Checkov en mode JSON
        cmd = ["checkov", "-f", file_path, "--output", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        try:
            # On essaie de lire le JSON proprement
            json_str = result.stdout
            # Parfois checkov met du texte avant le JSON, on cherche le début '{'
            start_index = json_str.find('{')
            if start_index != -1:
                json_str = json_str[start_index:]
                
            report_json = json.loads(json_str)
            
            # On prépare un résumé propre pour le Frontend
            summary = {
                "passed": report_json.get("summary", {}).get("passed", 0),
                "failed": report_json.get("summary", {}).get("failed", 0),
                "results": []
            }
            
            # On extrait les erreurs
            if "results" in report_json and "failed_checks" in report_json["results"]:
                for check in report_json["results"]["failed_checks"]:
                    summary["results"].append({
                        "id": check["check_id"],
                        "name": check["check_name"],
                        "resource": check["resource"],
                        "guide": check["guideline"]
                    })
            
            final_output = summary
            status = "Success"
        except:
            # Si le JSON plante, on renvoie le texte brut nettoyé
            clean_text = clean_ansi_codes(result.stdout)
            final_output = {"error": "Raw Output", "raw": clean_text}
            status = "Partial"

    except Exception as e:
        final_output = {"error": str(e)}
        status = "Error"

    # Sauvegarde DB
    table.put_item(Item={
        'scan_id': scan_id,
        'date': str(datetime.now()),
        'type': 'SAST (Code)',
        'status': status,
        'details': str(final_output)[:300] + "..." # On coupe pour pas surcharger
    })

    if os.path.exists(file_path):
        os.remove(file_path)

    return {"scan_id": scan_id, "data": final_output}

@app.post("/scan-cloud")
async def scan_cloud():
    scan_id = str(uuid.uuid4())
    
    try:
        # Prowler (Mode rapide IAM)
        cmd = ["prowler", "aws", "--services", "iam", "--ignore-exit-code-3"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Nettoyage
        clean_text = clean_ansi_codes(result.stdout)
        status = "Success"
    except Exception as e:
        clean_text = str(e)
        status = "Error"

    table.put_item(Item={
        'scan_id': scan_id,
        'date': str(datetime.now()),
        'type': 'CSPM (Cloud)',
        'status': status,
        'details': clean_text[:300] + "..."
    })

    return {"scan_id": scan_id, "output": clean_text}