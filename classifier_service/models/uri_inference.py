import os
import time
import pandas as pd
from models.safe_browsing_api import SafeURLExpander
from preprocessing.uri_feature_extractor import extract_features,extract_domain_features, canonicalize_domain, resolve_redirects
import joblib
from cache.uri_cache import get_cached_uri, cache_uri_result
from fastapi import FastAPI
from pydantic import BaseModel
import requests

MODEL_PATH = "models/uri_lgbm_model_domain.joblib"

class URLRequest(BaseModel):
    url: str


app = FastAPI(title="URI Phishing Classifier Service")

def load_model():
    return joblib.load(MODEL_PATH)

def predict_url(url, api_key=os.getenv("SAFE_BROWSING_API_KEY"), threshold=0.72):
    """
    Predict if URL is malicious using Safe Browsing + ML model.
    
    Priority order:
    1. Expand URL (resolve redirects)
    2. Cache check (using resolved URL)
    3. Benign URLs allowlist
    4. Google Safe Browsing API
    5. ML model
    
    Args:
        url: The URL to check
        api_key: Google Safe Browsing API key
        threshold: ML model classification threshold
    
    Returns:
        dict with prediction results
    """
    model = load_model()
    
    # 1️⃣ Expand URL (resolve redirects WITHOUT Safe Browsing checks yet)
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        session = requests.Session()
        session.max_redirects = 5
        
        response = session.head(
            url,
            allow_redirects=True,
            timeout=6,
            headers=headers
        )
        
        resolved_url = response.url
        print(f"Resolved URL: {resolved_url}")
        
    except requests.TooManyRedirects:
        print(f"⚠️  Too many redirects for {url}")
        resolved_url = url
    except requests.Timeout:
        print(f"⚠️  Timeout expanding {url}")
        resolved_url = url
    except requests.RequestException as e:
        print(f"⚠️  Failed to expand {url}: {e}")
        resolved_url = url
    
    # 2️⃣ Cache check (using resolved URL, not canonical)
    cached = get_cached_uri(resolved_url)
    if cached:
        print(f"✓ Found in cache")
        cached["source"] = "cache"
        return cached
    
    # Get canonical form for feature extraction later
    canonical = canonicalize_domain(resolved_url)
    
    # 3️⃣ Benign URLs allowlist check
    tranco = pd.read_csv("datasets/tranco_20122025.csv", header=None)
    benign_urls = tranco[1]
    df_benign_urls = pd.DataFrame({
        "domain": benign_urls,
    })
    
    # Check both original URL and resolved URL
    if (canonical.lower().strip() in df_benign_urls["domain"].values or
        url.lower().strip() in df_benign_urls["domain"].values or
        resolved_url.lower().strip() in df_benign_urls["domain"].values):
        print(f"✓ Found in benign URLs list")
        result = {
            "url": url,
            "resolved_url": resolved_url,
            "prediction": "BENIGN",
            "probability": 0.0,
            "source": "benign_urls_list"
        }
        cache_uri_result(resolved_url, result)  # Cache with resolved URL
        return result
    
    # 4️⃣ Google Safe Browsing API check
    expander = SafeURLExpander(api_key)
    
    # Check both original and resolved URLs
    original_safety = expander.check_url_safety(url)
    resolved_safety = expander.check_url_safety(resolved_url) if resolved_url != url else original_safety
    
    # If either is malicious, flag it
    if original_safety['is_safe'] == False or resolved_safety['is_safe'] == False:
        print(f"⚠️  Google Safe Browsing detected threats")
        result = {
            "url": url,
            "resolved_url": resolved_url,
            "prediction": "PHISHING",
            "probability": 1.0,
            "source": "google_safe_browsing",
            "threats": original_safety['threats'] + resolved_safety['threats']
        }
        cache_uri_result(resolved_url, result)  # Cache with resolved URL
        return result
    
    # 5️⃣ ML model prediction
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
        "safe_browsing_status": "clean" if resolved_safety['is_safe'] else "unknown"
    }
    
    cache_uri_result(resolved_url, result)  # Cache with resolved URL
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

