from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import shutil
import os
import uuid

app = FastAPI()

# Autoriser tout le monde (pour que le Frontend marche)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"status": "Cloud Sentinel is Ready 🚀"}

@app.post("/scan-code")
async def scan_code(file: UploadFile = File(...)):
    # On simule un scan Checkov pour l'instant
    return {
        "filename": file.filename,
        "status": "Scan terminé",
        "findings": "0 erreurs (Simulation)"
    }

@app.post("/scan-cloud")
async def scan_cloud():
    # On simule un scan Prowler
    return {
        "status": "Audit AWS terminé",
        "score": "95/100 (Simulation)"
    }