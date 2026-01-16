import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import os

class XLMRPredictor:
    def __init__(self, model_path):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # use_fast=False is safer for XLM-R models with custom sentencepiece tokens
        self.tokenizer = AutoTokenizer.from_pretrained(model_path, use_fast=False)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
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

        # Index [0][1] is typically the 'phishing' class in binary classification
        phishing_prob = probs[0][1].item()
        label = "phishing" if phishing_prob >= 0.5 else "safe"

        return {
            "label": label,
            "confidence": round(phishing_prob, 4)
        }