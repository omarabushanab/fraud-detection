import torch
from transformers import XLMRobertaTokenizer, XLMRobertaForSequenceClassification

class PhishingDetector:
    def __init__(self, model_path="model"):
        self.tokenizer = XLMRobertaTokenizer.from_pretrained(model_path)
        self.model = XLMRobertaForSequenceClassification.from_pretrained(model_path)
        self.model.eval()  # evaluation mode

    @torch.no_grad()
    def predict(self, text: str):
        # Tokenize
        inputs = self.tokenizer(
            text,
            truncation=True,
            max_length=256,
            padding=True,
            return_tensors="pt"
        )

        # Forward pass
        outputs = self.model(**inputs)
        logits = outputs.logits
        probs = torch.softmax(logits, dim=1)

        # Class decision
        pred_class = torch.argmax(probs, dim=1).item()
        class_label = "Phishing/Spam" if pred_class == 1 else "Safe"

        return {
            "label": class_label,
            "confidence": float(probs[0][pred_class])
        }

# from inference import PhishingDetector

# detector = PhishingDetector(model_path="model")

# text = "Urgent: Your bank account will be closed! Click here: http://fakebank.com"
# result = detector.predict(text)

# print(result)
