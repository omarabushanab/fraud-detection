import time
import pandas as pd
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

     # 1️⃣ Check cache
    cached = get_cached_uri(url)
    if cached:
        cached["source"] = "cache"
        print("Cache hit")
        return cached

    # Extract features
    features = extract_domain_features(canonicalize_domain(url))
    X = pd.DataFrame([features])

    prob = model.predict_proba(X)[0, 1]
    pred = int(prob >= threshold)

    result = {
        "url": url,
        "prediction": "PHISHING" if pred == 1 else "BENIGN",
        "probability": float(prob),
        "threshold": threshold,
        "source": "model"
    }

    # 3️⃣ Cache result
    cache_uri_result(url, result)

    return result


# test_url = input("Enter a URL to classify: ")
# result = predict_url(test_url)
@app.post("/classify_url")
def classify_url(request: URLRequest):
    return predict_url(request.url)

# print("===== URI INFERENCE RESULT =====")
# print(result)
# print("================================")

