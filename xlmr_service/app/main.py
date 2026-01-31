import os

from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

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
    urls: list[str] = []
    html: str | None = None

class BatchItem(BaseModel):
    text: str
    urls: list[str] = []
    html: str | None = None

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
    # Use direct attribute access for Pydantic objects
    return await predictor.predict(
        text = req.text,
        urls = req.urls if req.urls else [],
        raw_html = getattr(req, 'html', None) # Safely get html if added later
    )

@app.post("/predict_batch")
async def predict_batch(req: BatchRequest):
    results = await predictor.predict_batch(req.items)

    # Ensure triggers exists but do not compute SHAP here (performance)
    for res in results:
        if "triggers" not in res:
            res["triggers"] = []
    return results


@app.post("/analyze-full")
async def analyze_full(req: TextURLRequest):
    """
    Full analysis endpoint that returns structured explanation data.
    This is called by both the gmail service and the browser extension.
    """
    # 1. Run the prediction (which checks URLs first, then XLM-R)
    result = await predictor.predict(
        text=req.text, 
        urls=req.urls if req.urls else [], 
        raw_html=req.html
    )
    
    explanation = []
    reason_type = "safe"

    if result["label"] == "phishing":
        # 2. Check if it was caught by a URL
        if result.get("url") and result["url"].strip():
            reason_type = "url"
        else:
            # 3. If no malicious URL, determine if it was XLM-R or LLM
            if "LLM:" in result.get("reason", ""):
                reason_type = "llm"
            else:
                reason_type = "xlmr"
                # Get SHAP triggers for XLM-R classifications
                explanation = predictor.explain(req.text)
        
    return {
        "label": result["label"],
        "reason_type": reason_type,  # "url", "xlmr", "llm", or "safe"
        "reason": result.get("reason", ""),
        "confidence": result.get("confidence", 0.0),
        "malicious_url": result.get("url"),
        "triggers": explanation
    }