from fastapi import FastAPI
from pydantic import BaseModel
from .predictor import XLMRPredictor
import os

app = FastAPI(title="XLM-R Phishing Detection Service")

# Path to the folder created by download_model.py
MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "model"))

# Load model once on startup
predictor = XLMRPredictor(MODEL_PATH)

class TextRequest(BaseModel):
    text: str

@app.get("/health")
def health():
    return {"status": "ok", "device": str(predictor.device)}

@app.post("/predict")
def predict(req: TextRequest):
    return predictor.predict(req.text)