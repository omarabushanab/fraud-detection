import time
import pandas as pd
from models.safe_browsing_api import check_google_safe_browsing
from preprocessing.uri_feature_extractor import extract_features,extract_domain_features, canonicalize_domain
import joblib
from cache.uri_cache import get_cached_uri, cache_uri_result
from fastapi import FastAPI
from pydantic import BaseModel

MODEL_PATH = "models/uri_lgbm_model_domain.joblib"

class URLRequest(BaseModel):
    url: str


app = FastAPI(title="URI Phishing Classifier Service")

def load_model():
    return joblib.load(MODEL_PATH)


def predict_url(url, threshold=0.72):
    model = load_model()

    # 1️⃣ Cache check (canonicalized!)
    cached = get_cached_uri(canonicalize_domain(url))
    if cached:
        cached["source"] = "cache"
        return cached

    # 2️⃣ Google Safe Browsing
    gsb_result = check_google_safe_browsing(url)

    if gsb_result == "MALICIOUS":
        result = {
            "url": url,
            "prediction": "PHISHING",
            "probability": 1.0,
            "source": "google_safe_browsing"
        }
        cache_uri_result(canonicalize_domain(url), result)
        return result

    if gsb_result == "CLEAN":
        result = {
            "url": url,
            "prediction": "BENIGN",
            "probability": 0.0,
            "source": "google_safe_browsing"
        }
        cache_uri_result(canonicalize_domain(url), result)
        return result

    # 3️⃣ ML fallback
    features = extract_domain_features(canonicalize_domain(url))
    X = pd.DataFrame([features])

    prob = model.predict_proba(X)[0, 1]
    pred = prob >= threshold

    result = {
        "url": url,
        "prediction": "PHISHING" if pred else "BENIGN",
        "probability": float(prob),
        "threshold": threshold,
        "source": "model"
    }

    cache_uri_result(canonicalize_domain(url), result)
    return result

@app.get("/health")
def health_check():
    return {"status": "healthy"}
# test_url = input("Enter a URL to classify: ")
# result = predict_url(test_url)
@app.post("/classify_url")
def classify_url(request: URLRequest):
    return predict_url(request.url)

print("===== URI INFERENCE RESULT =====")
print(result)
print("================================")

