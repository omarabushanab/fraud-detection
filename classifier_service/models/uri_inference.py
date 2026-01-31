import os
import time
import pandas as pd
from models.safe_browsing_api import SafeURLExpander
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

def predict_url(url, api_key=os.getenv("SAFE_BROWSING_API_KEY"), threshold=0.72):
    """
    Predict if URL is malicious using Safe Browsing + ML model.
    
    Args:
        url: The URL to check
        api_key: Google Safe Browsing API key
        threshold: ML model classification threshold
    
    Returns:
        dict with prediction results
    """
    model = load_model()
    
    # Initialize Safe URL Expander
    expander = SafeURLExpander(api_key)
    
    # Safely resolve redirects with Safe Browsing checks
    resolution_result = expander.safe_resolve_redirects(url)
    
    # If Safe Browsing detected threats, return immediately
    if resolution_result['is_safe'] == False:
        print(f"⚠️  Google Safe Browsing detected threats")
        result = {
            "url": url,
            "resolved_url": resolution_result.get('final_url'),
            "prediction": "PHISHING",
            "probability": 1.0,
            "source": "google_safe_browsing",
            "threats": resolution_result['threats']
        }
        
        # Cache the result
        if resolution_result.get('final_url'):
            canonical = canonicalize_domain(resolution_result['final_url'])
            cache_uri_result(canonical, result)
        
        return result
    
    # Use resolved URL for further processing
    resolved_url = resolution_result.get('final_url', url)
    print(f"Resolved URL: {resolved_url}")
    
    canonical = canonicalize_domain(resolved_url)
    
    # 1️⃣ Cache check
    cached = get_cached_uri(canonical)
    if cached:
        cached["source"] = "cache"
        return cached
    
    # 2️⃣ At this point, Safe Browsing either returned CLEAN or UNKNOWN
    # Continue to ML model for final prediction
    features = extract_domain_features(canonical)
    X = pd.DataFrame([features])
    prob = model.predict_proba(X)[0, 1]
    pred = prob >= threshold
    
    result = {
        "url": url,
        "resolved_url": resolved_url,
        "prediction": "PHISHING" if pred else "BENIGN",
        "probability": float(prob),
        "threshold": threshold,
        "source": "model",
        "safe_browsing_status": "clean" if resolution_result['is_safe'] else "unknown"
    }
    
    cache_uri_result(canonical, result)
    return result


# def predict_url(url, threshold=0.72):
#     model = load_model()

#     url = resolve_redirects(url)
#     print(f"Resolved URL: {url}")

#     canonical = canonicalize_domain(url)

#     # 1️⃣ Cache check
#     cached = get_cached_uri(canonical)
#     if cached:
#         cached["source"] = "cache"
#         return cached

#     # 2️⃣ Google Safe Browsing (blocklist only)
#     gsb_result = check_google_safe_browsing(url)

#     if gsb_result == "MALICIOUS":
#         result = {
#             "url": url,
#             "prediction": "PHISHING",
#             "probability": 1.0,
#             "source": "google_safe_browsing"
#         }
#         cache_uri_result(canonical, result)
#         return result

#     # 3️⃣ ML fallback (GSB CLEAN or UNKNOWN)
#     features = extract_domain_features(canonical)
#     X = pd.DataFrame([features])

#     prob = model.predict_proba(X)[0, 1]
#     pred = prob >= threshold

#     result = {
#         "url": url,
#         "prediction": "PHISHING" if pred else "BENIGN",
#         "probability": float(prob),
#         "threshold": threshold,
#         "source": "model"
#     }

#     cache_uri_result(canonical, result)
#     return result


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

