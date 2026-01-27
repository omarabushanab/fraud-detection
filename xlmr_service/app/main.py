import os

from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware  #

from app.predictor import XLMRPredictor

app = FastAPI(title="XLM-R Phishing Detection Service")

# 1. Define the origins that are allowed to talk to your API
origins = [
    "http://localhost",
    "http://localhost:8002",
    # Use your actual Extension ID from chrome://extensions
    "chrome-extension://ogdpbgagjdkapaokiggidfmbpmpfdgee", 
    "https://jonell-ardeid-interpervasively.ngrok-free.dev"
]

# 2. Add the middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],            # Permits these domains
    # allow_credentials=True,          # Allows cookies/auth headers
    allow_methods=["*"],              # Permits all methods (GET, POST, etc.)
    allow_headers=["*"],              # Permits all headers
)

# Allow override via env (useful if model is mounted instead of baked in)
MODEL_PATH = os.getenv(
    "MODEL_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "model", "xlm-r-phishing-final-4")),
)

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model directory not found at {MODEL_PATH}")

# Load model once on startup
predictor = XLMRPredictor(MODEL_PATH)


class TextRequest(BaseModel):
    text: str

class TextURLRequest(BaseModel):
    text: str
    urls: list[str]

class BatchItem(BaseModel):
    text: str
    urls: list[str]

class BatchRequest(BaseModel):
    items: list[BatchItem]

@app.get("/health")
def health():
    return {"status": "ok", "device": str(predictor.device)}


@app.post("/explain")
def explain(req: TextRequest):
    return {"triggers": predictor.explain(req.text)}

@app.post("/predict")
async def predict(req: TextURLRequest):
    return await predictor.predict(req.text, req.urls)

@app.post("/predict_batch")
async def predict_batch(req: BatchRequest):
    return await predictor.predict_batch(req.items)

@app.post("/analyze_full")
async def analyze_full(req: TextRequest):
    # 1. Run the prediction (which checks URLs first, then XLM-R)
    result = await predictor.predict_for_analyze(req.text)
    
    explanation = []
    reason_type = "safe"

    if result["label"] == "phishing":
        # 2. Check if it was caught by a URL
        if result.get("url") and result["url"].strip():
            reason_type = "url"
        else:
            # 3. If no malicious URL, get SHAP triggers for XLM-R
            reason_type = "xlmr"
            explanation = predictor.explain(req.text)
        
    return {
        "label": result["label"],
        "reason_type": reason_type, # "url" or "xlmr"
        "malicious_url": result.get("url"),
        "triggers": explanation
    }