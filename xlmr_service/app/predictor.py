import torch
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import os
import shap 
from urlextract import URLExtract
import httpx


#Explicit Model Dir: Ensure the predictor doesn't try to download weights from the internet if they are already present locally.
os.environ["TRANSFORMERS_OFFLINE"] = "1"
    
CLASSIFIER_SERVICE_URL = os.getenv("CLASSIFIER_URL", "http://classifier_service:8003/classify_url")


class XLMRPredictor:
    def __init__(self, model_path):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # use_fast=False is safer for XLM-R models with custom sentencepiece tokens
        self.tokenizer = AutoTokenizer.from_pretrained(model_path, use_fast=False)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path, local_files_only=True)
        self.model.to(self.device)
        self.model.eval()
        self.explainer_pipeline = pipeline(
            "text-classification", 
            model=self.model, 
            tokenizer=self.tokenizer, 
            device=self.device,
            top_k=None
        )
        self.explainer = shap.Explainer(self.explainer_pipeline)

    # predictor.py
    def explain(self, text):
        shap_values = self.explainer([text])
        tokens = shap_values.data[0]
        values = shap_values.values[0][:, 1]
        
        # Filter for impact > 0.05 and ignore tokens shorter than 3 chars
        triggers = [
            tokens[i].replace('Ġ', '').strip() 
            for i, val in enumerate(values) 
            if val > 0.05 and len(tokens[i].replace('Ġ', '').strip()) > 2
        ]
        return list(set(triggers))

    async def predict(self, text: str, urls: list[str] = []):
        print("Extracted URLs:", urls)
        url = None
        for u in urls:
            url = u
            async with httpx.AsyncClient() as client:
                try:
                    response = await client.post(CLASSIFIER_SERVICE_URL, json={"url": url}, timeout=60.0)
                    data = response.json()
                    # Map labels to your Gmail logic (Safe/Malicious)
                    label = "phishing" if data["prediction"] == "PHISHING" else "Safe"
                    print(f"Classifier response for {url}: {data}")
                    if(label=="phishing"):
                        return {
                            "url": url,
                            "label": label,
                            "confidence": data["probability"]}
                except Exception as e:
                    print(f"Connection error to classifier: {e}")
                    return "Safe", 0.0
        
        #tokenize and predict 
        inputs = self.tokenizer(
            text, 
            return_tensors="pt", 
            truncation=True, 
            padding=True, 
            max_length=512
        ).to(self.device)

        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)

        # probs[0][0] is 'safe', probs[0][1] is 'phishing'
        safe_prob = probs[0][0].item()
        phishing_prob = probs[0][1].item()

        if phishing_prob >= 0.5:
            label = "phishing"
            confidence = phishing_prob
        else:
            label = "safe"
            confidence = safe_prob  # This will now show 0.999 if it is very sure it is safe
        #get boudy async
        #return 3la 7asab
        if url is None:
            url = " "
        return {
            "url": url,
            "label": label,
            "confidence": round(confidence, 4)
        }
    
    async def predict_batch(self, texts: list[str]):
        # 1. Batch Tokenization (Efficient)
        inputs = self.tokenizer(
            texts, 
            return_tensors="pt", 
            truncation=True, 
            padding=True, # Critical for batching
            max_length=512
        ).to(self.device)

        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)

        results = []
        for i in range(len(texts)):
            safe_prob = probs[i][0].item()
            phishing_prob = probs[i][1].item()
            
            label = "phishing" if phishing_prob >= 0.5 else "safe"
            confidence = phishing_prob if label == "phishing" else safe_prob
            
            results.append({
                "label": label,
                "confidence": round(confidence, 4)
            })
        return results