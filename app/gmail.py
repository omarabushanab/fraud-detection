import base64
import json
import os
import pickle

from fastapi import FastAPI, Request
import uvicorn

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request as GRequest

from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import torch.nn.functional as F


# ======================
# CONFIG
# ======================
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
MODEL_PATH = r"G:\.shortcut-targets-by-id\1x507Fs2GpRNcZXoBsd7NiSFQv_6mQ200\xlm-r-phishing-final"
LAST_HISTORY_ID = None

# ibrahim

# ======================
# FASTAPI APP
# ======================
app = FastAPI()


# ======================
# GMAIL AUTH (OAuth)
# ======================
def get_gmail_service():
    creds = None

    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as f:
            creds = pickle.load(f)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(GRequest())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", SCOPES
            )
            creds = flow.run_local_server(port=0)

        with open("token.pickle", "wb") as f:
            pickle.dump(creds, f)

    return build("gmail", "v1", credentials=creds)


# ======================
# ML MODEL
# ======================
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_PATH, local_files_only=True
)
model.eval()

def get_or_create_malicious_label(service):
    labels = service.users().labels().list(userId="me").execute()["labels"]

    for label in labels:
        if label["name"].lower() == "malicious":
            return label["id"]

    label = service.users().labels().create(
        userId="me",
        body={
            "name": "malicious",
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show"
        }
    ).execute()

    return label["id"]


def move_to_malicious(service, msg_id, label_id):
    service.users().messages().modify(
        userId="me",
        id=msg_id,
        body={
            "addLabelIds": [label_id],
            "removeLabelIds": ["INBOX"]
        }
    ).execute()

def classify_text(text):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = F.softmax(outputs.logits, dim=-1)

    idx = torch.argmax(probs, dim=-1).item()
    label = "Safe" if idx == 0 else "Malicious"
    confidence = probs[0][idx].item()

    return label, confidence


# ======================
# PUSH ENDPOINT
# ======================
@app.post("/gmail/push")
async def gmail_push(request: Request):
    envelope = await request.json()

    if "message" not in envelope:
        return {"status": "ignored"}

    data = json.loads(base64.b64decode(envelope["message"]["data"]).decode())
    history_id = data["historyId"]

    print(f"🔔 Push notification received (historyId={history_id})")


    service = get_gmail_service()

    malicious_label_id = get_or_create_malicious_label(service)


    global LAST_HISTORY_ID

    if LAST_HISTORY_ID is None:
        LAST_HISTORY_ID = history_id
        print("ℹ️ History baseline set, waiting for next email")
        return {"status": "baseline set"}

    history = service.users().history().list(
        userId="me",
        startHistoryId=LAST_HISTORY_ID,
        historyTypes=["messageAdded"]
    ).execute()

    LAST_HISTORY_ID = history_id

    for h in history.get("history", []):
        for msg in h.get("messagesAdded", []):
            msg_id = msg["message"]["id"]

            email = service.users().messages().get(
                userId="me",
                id=msg_id,
                format="full"
            ).execute()
            print(email['snippet'])


            label, conf = classify_text(email['snippet'])

            print("\n📧 New Email Received")
            print(f"🧪 Verdict: {label} ({conf:.2%})")

            if label == "Malicious":
                move_to_malicious(service, msg_id, malicious_label_id)
                print("🚨 Email moved to 'malicious' and removed from Inbox")


    return {"status": "ok"}


# ======================
# RUN SERVER
# ======================
if __name__ == "__main__":
    uvicorn.run("gmail:app", host="0.0.0.0", port=8000)
