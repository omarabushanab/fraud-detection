import os

from fastapi import FastAPI
from pydantic import BaseModel

from app.predictor import XLMRPredictor

app = FastAPI(title="XLM-R Phishing Detection Service")

# Allow override via env (useful if model is mounted instead of baked in)
MODEL_PATH = os.getenv(
    "MODEL_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "model", "xlm-r-phishing-final")),
)

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model directory not found at {MODEL_PATH}")

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