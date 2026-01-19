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

from google.oauth2 import id_token
from google.auth.transport import requests

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request as GRequest
from googleapiclient.errors import HttpError
from google_auth_oauthlib.flow import Flow


# ======================
# CONFIG
# ======================



CLIENT_CONFIG = json.load(open("credentials.json"))

# Updated to include identity scopes
SCOPES = [
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/userinfo.email',
    'openid'
]
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

async def get_user_service(email_address: str):
    # 1. Look for the user's token in Redis instead of a local file
    token_json = await db.get(f"token:{email_address}")
    
    if not token_json:
        # If no token exists, the user needs to log in via your UI first
        print(f"❌ No credentials found in Redis for {email_address}")
        return None

    # 2. Reconstruct the credentials from the stored JSON
    creds_data = json.loads(token_json)
    creds = Credentials.from_authorized_user_info(creds_data, SCOPES)

    # 3. Refresh the token if it has expired
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(GRequest())
        # Update the refreshed token back in Redis
        await db.set(f"token:{email_address}", creds.to_json())

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
    
    # Verify the push contains valid data
    if "message" not in envelope or "data" not in envelope["message"]:
        return {"status": "ignored"}

    # 1. Decode the notification payload from Google Pub/Sub
    data = json.loads(base64.b64decode(envelope["message"]["data"]).decode())
    email_address = data.get("emailAddress") 
    current_history_id = int(data["historyId"])
    print(f"🔔 Push notification received for {email_address} (historyId={current_history_id})")

    # 2. Get the dynamic Gmail API service for THIS specific user
    service = await get_user_service(email_address)
    if not service:
        return {"status": "user_not_authenticated"}
    
    # 3. Retrieve THIS user's last processed state from Redis
    last_known_id = await db.get(f"history:{email_address}")

    # Handle first-time baseline setup for a new user
    if last_known_id is None:
        await db.set(f"history:{email_address}", current_history_id)
        print(f"ℹ️ History baseline set for {email_address}.")
        return {"status": "baseline set"}

    # Ensure the label exists for this specific user
    malicious_label_id = get_or_create_malicious_label(service)

    try:
        # 4. Fetch changes since THIS user's last_known_id
        history_response = service.users().history().list(
            userId="me",
            startHistoryId=last_known_id,
            historyTypes=["messageAdded"]
        ).execute()

        # 5. Process new messages if they exist in the history
        if "history" in history_response:
            for h in history_response["history"]:
                for added in h.get("messagesAdded", []):
                    msg_id = added["message"]["id"]

                    # Fetch full email content to see snippet and attachments
                    email = service.users().messages().get(
                        userId="me", id=msg_id, format="full"
                    ).execute()

                    is_malicious_found = False
                    
                    # Check the snippet first (fast check)
                    label, conf = await classify_text(email.get('snippet', ''))
                    print(f"⚖️ Verdict for {email_address} Mail Body: {label} ({conf:.2%})")
                    
                    if label == "Malicious":
                        is_malicious_found = True
                    else:
                        # Deep scan attachments (PDF and Text)
                        all_contents = get_parts_content(service, msg_id, email['payload'])
                        for item in all_contents:
                            if not item["content"].strip():
                                continue
                                
                            label, conf = await classify_text(item["content"])
                            print(f"⚖️ Verdict for {item['source']}: {label} ({conf:.2%})")

                            if label == "Malicious":
                                is_malicious_found = True
                                break

                    # 6. Take Action per User
                    if is_malicious_found:
                        move_to_malicious(service, msg_id, malicious_label_id)
                        print(f"🚨 ACTION: Moved {msg_id} for {email_address} to Malicious folder.")
                    else:
                        print(f"✅ ACTION: Kept {msg_id} in {email_address} Inbox.")

    except HttpError as error:
        # 404 means the History ID is too old (expires after 7 days)
        if error.resp.status == 404:
            print(f"⚠️ History ID expired for {email_address}. Resetting baseline...")
        else:
            print(f"❌ API Error for {email_address}: {error}")
    
    # 7. Update the state in Redis for this user
    await db.set(f"history:{email_address}", current_history_id)
    return {"status": "ok"}


@app.get("/login")
async def login():
    # Use the credentials.json to create an OAuth flow
    flow = Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=SCOPES,
        redirect_uri="https://jonell-ardeid-interpervasively.ngrok-free.dev/callback"
    )
    auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline')
    return {"auth_url": auth_url}

@app.get("/callback")
async def oauth_callback(code: str):
    flow = Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=SCOPES,
        redirect_uri="https://jonell-ardeid-interpervasively.ngrok-free.dev/callback"
    )
    flow.fetch_token(code=code)
    creds = flow.credentials

    # FIX: Decode the ID token to get the email dictionary
    try:
        # verify_oauth2_token decodes the JWT string into a dictionary
        id_info = id_token.verify_oauth2_token(
            creds.id_token, 
            requests.Request(), 
            CLIENT_CONFIG['installed']['client_id']
        )
        email = id_info.get('email')
    except Exception as e:
        print(f"ID Token verification failed: {e}")
        # Fallback to UserInfo API if token decoding fails
        user_info_service = build('oauth2', 'v2', credentials=creds)
        user_info = user_info_service.userinfo().get().execute()
        email = user_info['email']

    if not email:
        return {"status": "error", "message": "Could not retrieve email address"}

    # Save the real token and setup watching in Redis
    await db.set(f"token:{email}", creds.to_json())
    
    gmail_service = build('gmail', 'v1', credentials=creds)
    gmail_service.users().watch(
        userId='me', 
        body={'topicName': 'projects/unifonic-481420/topics/gmail-push'}
    ).execute()

    return {"status": "success", "user": email, "message": "Monitoring enabled!"}
# ======================
# RUN SERVER
# ======================
if __name__ == "__main__":
    uvicorn.run("gmail:app", host="0.0.0.0", port=8002)
