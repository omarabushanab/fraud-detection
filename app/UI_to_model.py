from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import torch.nn.functional as F
from pathlib import Path

model_path = (
    Path(__file__).resolve()
    .parents[1]          # fraud-detection/
    / "xlm-r-phishing-final"
)
model_path = str(model_path)
tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
model = AutoModelForSequenceClassification.from_pretrained(model_path, local_files_only=True)
model.eval()

def classify_text(text):
    
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)

    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probs = F.softmax(logits, dim=-1)

    predicted = torch.argmax(probs, dim=-1).item()
    confidence = probs[0][predicted].item()

    labels = {0: "Safe / Not Malicious", 1: "Malicious"}
    return labels[predicted], confidence

text = "Congratulations! You have won a prize! Click here to claim."
label, conf = classify_text(text)
print("Prediction:", label)
print("Confidence:", conf)
