import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import os

#Explicit Model Dir: Ensure the predictor doesn't try to download weights from the internet if they are already present locally.
os.environ["TRANSFORMERS_OFFLINE"] = "1"
    

class XLMRPredictor:
    def __init__(self, model_path):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # use_fast=False is safer for XLM-R models with custom sentencepiece tokens
        self.tokenizer = AutoTokenizer.from_pretrained(model_path, use_fast=False)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path, local_files_only=True)
        self.model.to(self.device)
        self.model.eval()

    def predict(self, text: str):
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

        return {
            "label": label,
            "confidence": round(confidence, 4)
        }