import time
import pandas as pd
from models.safe_browsing_api import check_google_safe_browsing
from preprocessing.uri_feature_extractor import extract_features,extract_domain_features, canonicalize_domain, resolve_redirects
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

    url = resolve_redirects(url)
    print(f"Resolved URL: {url}")

    canonical = canonicalize_domain(url)

    # 1️⃣ Cache check
    cached = get_cached_uri(canonical)
    if cached:
        cached["source"] = "cache"
        return cached

    # 2️⃣ Google Safe Browsing (blocklist only)
    gsb_result = check_google_safe_browsing(url)

    if gsb_result == "MALICIOUS":
        result = {
            "url": url,
            "prediction": "PHISHING",
            "probability": 1.0,
            "source": "google_safe_browsing"
        }
        cache_uri_result(canonical, result)
        return result

    # 3️⃣ ML fallback (GSB CLEAN or UNKNOWN)
    features = extract_domain_features(canonical)
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

    cache_uri_result(canonical, result)
    return result


@app.get("/health")
def health_check():
    return {"status": "healthy"}
test_url = input("Enter a URL to classify: ")
result = predict_url(test_url)
@app.post("/classify_url")
def classify_url(request: URLRequest):
    return predict_url(request.url)

print("===== URI INFERENCE RESULT =====")
print(result)
print("================================")

