import pandas as pd
from core.preprocessing.uri_feature_extractor import extract_features
import joblib

MODEL_PATH = "core/models/uri_lgbm_model.joblib"

def load_model():
    return joblib.load(MODEL_PATH)

def predict_url(url, threshold=0.5):
    model = load_model()

    # Extract features
    features = extract_features(url)
    X = pd.DataFrame([features])

    prob = model.predict_proba(X)[0, 1]
    pred = int(prob >= threshold)

    return {
        "url": url,
        "prediction": "PHISHING" if pred == 1 else "BENIGN",
        "probability": float(prob)
    }

def main():
    test_url = input("Enter a URL to classify: ")
    result = predict_url(test_url)
    print(result)

if __name__ == "__main__":
    main()
