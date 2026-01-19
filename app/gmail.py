import base64
import json
import os
import pickle
import fitz  # PyMuPDF
import io
from fastapi import FastAPI, Request
import uvicorn

import httpx
import redis.asyncio as redis
from google.oauth2.credentials import Credentials

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request as GRequest
from googleapiclient.errors import HttpError



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


# Configuration for Microservice Communication
DETECTOR_SERVICE_URL = os.getenv("DETECTOR_URL", "http://xlmr_service:8001/predict")
# Initialize Redis for multi-user state
db = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379"), decode_responses=True)

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

async def classify_text(text):
    """Calls your existing containerized model service"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(DETECTOR_SERVICE_URL, json={"text": text}, timeout=10.0)
            data = response.json()
            # Map labels to your Gmail logic (Safe/Malicious)
            label = "Malicious" if data["label"] == "phishing" else "Safe"
            return label, data["confidence"]
        except Exception as e:
            print(f"Connection error to detector: {e}")
            return "Safe", 0.0
        
def get_attachment_text(service, msg_id, parts):
    attachment_texts = []
    for part in parts:
        if part.get('filename'):  # This part is an attachment
            attachment_id = part['body'].get('attachmentId')
            if attachment_id:
                # Fetch the actual attachment data
                attachment = service.users().messages().attachments().get(
                    userId='me', messageId=msg_id, id=attachment_id
                ).execute()
                
                data = attachment.get('data')
                if data:
                    # Decode from base64url to string
                    decoded_data = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                    attachment_texts.append(f"\n[Attachment: {part['filename']}]\n{decoded_data}")
        
        # Recursively check nested parts (common in multi-part emails)
        if 'parts' in part:
            attachment_texts.extend(get_attachment_text(service, msg_id, part['parts']))
            
    return " ".join(attachment_texts)

def get_parts_content(service, msg_id, payload):
    parts_to_classify = []
    
    # 1. Get the main body/snippet
    snippet = payload.get('snippet', '')
    if snippet:
        parts_to_classify.append({"source": "Email Body", "content": snippet})

    def walk_parts(parts):
        for part in parts:
            filename = part.get('filename')
            if filename:
                attachment_id = part['body'].get('attachmentId')
                if attachment_id:
                    attachment = service.users().messages().attachments().get(
                        userId='me', messageId=msg_id, id=attachment_id
                    ).execute()
                    
                    raw_data = base64.urlsafe_b64decode(attachment.get('data'))
                    
                    # --- PDF HANDLING ---
                    if filename.lower().endswith('.pdf'):
                        print(f"📄 Extracting text from PDF: {filename}")
                        try:
                            pdf_stream = io.BytesIO(raw_data)
                            with fitz.open(stream=pdf_stream, filetype="pdf") as doc:
                                text = ""
                                for page in doc:
                                    text += page.get_text()
                            decoded_data = text
                        except Exception as e:
                            print(f"❌ PDF extraction failed: {e}")
                            decoded_data = ""
                    
                    # --- TEXT/PLAIN HANDLING ---
                    else:
                        decoded_data = raw_data.decode('utf-8', errors='ignore')
                    
                    if decoded_data.strip():
                        parts_to_classify.append({
                            "source": f"Attachment: {filename}",
                            "content": decoded_data
                        })
                        print(f"✅ Extracted content from {filename}")

            if 'parts' in part:
                walk_parts(part['parts'])

    if 'parts' in payload:
        walk_parts(payload['parts'])
        
    return parts_to_classify
# ======================
# PUSH ENDPOINT
# ======================

@app.post("/gmail/push")
async def gmail_push(request: Request):
    envelope = await request.json()
    email_address = envelope["message"]["attributes"].get("userEmail")
    # 1. Fetch user state from Redis
    user_data = await db.hgetall(f"user:{email_address}")
    if not user_data:
        return {"status": "user not found"}
    
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
                    # ... inside your 'for added in h.get("messagesAdded", [])' loop:
                    msg_id = added["message"]["id"]

                    # Get full email content (required to see the 'payload' and 'parts')
                    email = service.users().messages().get(
                        userId="me", id=msg_id, format="full"
                    ).execute()

                    is_malicious_found = False
                    # Populate the list with Body + All Attachments individually
                    all_contents = get_parts_content(service, msg_id, email['payload'])

                    label, conf = classify_text(email['snippet'])
                    print(f"⚖️ Verdict for Mail Body: {label} ({conf:.2%})")
                    
                    if label == "Malicious":
                        is_malicious_found = True
                    else:
                        for item in all_contents:
                            if not item["content"].strip():
                                print(f"⚠️ {item['source']} is empty, skipping...")
                                continue
                                
                            label, conf = classify_text(item["content"])
                            print(f"⚖️ Verdict for {item['source']}: {label} ({conf:.2%})")

                            if label == "Malicious":
                                is_malicious_found = True
                                break

                    # Take Action
                    if is_malicious_found:
                        service.users().messages().modify(
                            userId='me', id=msg_id,
                            body={'addLabelIds': [malicious_label_id], 'removeLabelIds': ['INBOX']}
                        ).execute()
                        print(f"🚨 ACTION: Moved {msg_id} to Malicious folder.")
                    else:
                        print(f"✅ ACTION: All parts passed. Kept {msg_id} in Inbox.")

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
    uvicorn.run("gmail:app", host="0.0.0.0", port=8002)
