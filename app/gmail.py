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
from googleapiclient.errors import HttpError

@app.post("/gmail/push")
async def gmail_push(request: Request):
    envelope = await request.json()
    if "message" not in envelope:
        return {"status": "ignored"}

    # 1. Decode historyId from the notification
    data = json.loads(base64.b64decode(envelope["message"]["data"]).decode())
    current_history_id = data["historyId"]
    print(f"🔔 Push notification received (historyId={current_history_id})")

    service = get_gmail_service()
    malicious_label_id = get_or_create_malicious_label(service)

    global LAST_HISTORY_ID

    # 2. Handle first run
    if LAST_HISTORY_ID is None:
        LAST_HISTORY_ID = current_history_id
        print("ℹ️ History baseline set.")
        return {"status": "baseline set"}

    try:
        # 3. Fetch history since the last known ID
        history_response = service.users().history().list(
            userId="me",
            startHistoryId=LAST_HISTORY_ID,
            historyTypes=["messageAdded"]
        ).execute()

        # Update baseline for next time
        LAST_HISTORY_ID = current_history_id

        # 4. Process only if there are new messages
        if "history" in history_response:
            for h in history_response["history"]:
                # Check for messages added to Inbox
                for added in h.get("messagesAdded", []):
                    msg_id = added["message"]["id"]
                    
                    # Get full email content
                    email = service.users().messages().get(
                        userId="me", id=msg_id, format="full"
                    ).execute()
                    
                    body_text = email.get('snippet', '')
                    label, conf = classify_text(body_text)

                    print(f"\n📧 Email Snippet: {body_text[:50]}...")
                    print(f"🧠 Verdict: {label} ({conf:.2%})")

                    # 5. Take Action
                    if label == "Malicious":
                        # Add Malicious Label and Remove INBOX Label
                        service.users().messages().modify(
                            userId='me',
                            id=msg_id,
                            body={
                                'addLabelIds': [malicious_label_id],
                                'removeLabelIds': ['INBOX']
                            }
                        ).execute()
                        print(f"🚨 ACTION: Moved message {msg_id} to Malicious folder.")
                    else:
                        print("✅ ACTION: Kept in Inbox.")

    except HttpError as error:
        if error.resp.status == 404:
            print("⚠️ History ID expired. Resetting baseline...")
            LAST_HISTORY_ID = current_history_id
        else:
            print(f"❌ API Error: {error}")

    return {"status": "ok"}
# ======================
# RUN SERVER
# ======================
if __name__ == "__main__":
    get_gmail_service()
    uvicorn.run("gmail:app", host="0.0.0.0", port=8000)
