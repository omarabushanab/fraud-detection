import asyncio
import base64
import json
import os
import pickle
import fitz  # PyMuPDF
import io
from fastapi import FastAPI, Request, Form
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
from pathlib import Path
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from fastapi.responses import HTMLResponse, JSONResponse
import re
from bs4 import BeautifulSoup

from fastapi.middleware.cors import CORSMiddleware  #
from contextlib import asynccontextmanager

# ======================
# CONFIG
# ======================



credentials_raw = os.getenv("GOOGLE_CREDENTIALS_JSON")
if not credentials_raw:
    raise ValueError("GOOGLE_CREDENTIALS_JSON environment variable is not set!")

CLIENT_CONFIG = json.loads(credentials_raw)

BASE_URL = os.getenv("BASE_URL", "https://jonell-ardeid-interpervasively.ngrok-free.dev")
REDIRECT_URI = f"{BASE_URL}/callback"
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



# Configuration for Microservice Communication
DETECTOR_SERVICE_URL = os.getenv("DETECTOR_URL", "http://xlmr_service:8001/predict")
# Initialize Redis for multi-user state
db = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379"), 
                    decode_responses=True,
                    health_check_interval=30,
                    retry_on_timeout=True)

class EmailRequest(BaseModel):
    email: str

html_content = ""
# HTML template embedded in the code
with open("template.html", "r", encoding="utf-8") as f:
    html_content = f.read()

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

async def classify_text(text, found_uris = []):
    """Calls your existing containerized model service"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(DETECTOR_SERVICE_URL, json={"text": text, "urls": found_uris}, timeout=10.0)
            response.raise_for_status() # Raise error for bad responses
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
        
    # Use the msg_id to get the full message details from the service
    message_details = service.users().messages().get(userId='me', id=msg_id).execute()

    # Check the labels to see if 'SENT' is present
    labels = message_details.get('labelIds', [])

    if 'INBOX' in labels:
        # This code only runs for RECEIVED mail (not sent)
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

def extract_all_uris(service, msg_id, payload):
    """
    Extracts all clickable/embedded URIs from the email body (HTML) 
    and from inside PDF attachments.
    """
    all_uris = set()
    # Regex to catch plain-text URLs that aren't wrapped in <a> tags
    url_regex = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'

    def walk_parts(parts):
        for part in parts:
            mime_type = part.get('mimeType')
            body = part.get('body', {})
            filename = part.get('filename', '')

            # --- 1. SCAN HTML BODY ---
            if mime_type == 'text/html' and 'data' in body:
                raw_html = base64.urlsafe_b64decode(body['data']).decode('utf-8', errors='ignore')
                soup = BeautifulSoup(raw_html, 'html.parser')
                # Extract actual 'href' destinations
                for a in soup.find_all('a', href=True):
                    href = a['href']
                    if href.startswith('mailto:'):
                        continue
                    all_uris.add(href)
                # Also run regex to catch raw text links in HTML
                all_uris.update(re.findall(url_regex, raw_html))

            # --- 2. SCAN PDF EMBEDDED LINKS ---
            elif filename.lower().endswith('.pdf') and 'attachmentId' in body:
                try:
                    attachment = service.users().messages().attachments().get(
                        userId='me', messageId=msg_id, id=body['attachmentId']).execute()
                    pdf_data = base64.urlsafe_b64decode(attachment['data'])
                    
                    with fitz.open(stream=io.BytesIO(pdf_data), filetype="pdf") as doc:
                        for page in doc:
                            # This is the critical part for "hidden" hacking links
                            for link in page.get_links():
                                if 'uri' in link:
                                    all_uris.add(link['uri'])
                            
                            # Also check text for written-out URLs
                            all_uris.update(re.findall(url_regex, page.get_text()))
                except Exception as e:
                    print(f"❌ Error scanning PDF {filename}: {e}")

            if 'parts' in part:
                walk_parts(part['parts'])

    if 'parts' in payload:
        walk_parts(payload['parts'])
    elif 'body' in payload:
        walk_parts([payload])

    return list(all_uris)


# ======================
# PUSH ENDPOINT
# ======================
@asynccontextmanager
async def lifespan(app: FastAPI):
    keys = await db.keys("token:*")
    active_tasks = []

    for key in keys:
        email = key.split(":", 1)[1]
        print(f"Launching lifespan worker for: {email}")

        task = asyncio.create_task(processing_worker(email))
        active_tasks.append(task)
    
    yield

    print("shutting down workers...")
    for task in active_tasks:
        task.cancel()
    
    await asyncio.gather(*active_tasks, return_exceptions=True)
    await db.close()
    print(" shutdown complete.")

app = FastAPI(lifespan=lifespan)

# 2. Add the middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],            # Permits these domains
    # allow_credentials=True,          # Allows cookies/auth headers
    allow_methods=["*"],              # Permits all methods (GET, POST, etc.)
    allow_headers=["*"],              # Permits all headers
)

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
    
    try:

        history_response = service.users().history().list(
            userId="me",
            startHistoryId=last_known_id,
            historyTypes=["messageAdded"]
        ).execute()

        await db.set(f"history:{email_address}", current_history_id)

        if "history" in history_response:
            for h in history_response["history"]:
                for added in h.get("messagesAdded", []):
                    msg_id = added["message"]["id"]
                    is_duplicate = await db.get(f"processed:{msg_id}:{email_address}")
                    if is_duplicate:
                        print(f"⚠️ Message {msg_id} for {email_address} already queued. Skipping duplicate.")
                        continue
                    await db.lpush(f"queue:{email_address}", msg_id)
                    print(f"➕ Queued message {msg_id} for {email_address} processing.")
                    await db.setex(f"processed:{msg_id}:{email_address}", 86400, "1")  # 1 day expiry
        # await db.set(f"history:{email_address}", current_history_id)
    except HttpError as error:
        # 404 means the History ID is too old (expires after 7 days)
        if error.resp.status == 404:
            print(f"⚠️ History ID expired for {email_address}. Resetting baseline...")
            await db.set(f"history:{email_address}", current_history_id)
        else:
            print(f"❌ API Error for {email_address}: {error}")
    return {"status": "ok"}

async def processing_worker(email_address: str):
    print(f" Worker started for {email_address}")
    while True:
        try:
            #fetch up to 8 messages from the queue
            msg_ids = []
            for _ in range(8):
                msg_id = await db.rpop(f"queue:{email_address}")
                if msg_id:
                    msg_ids.append(msg_id)
                else:
                    break
            
            if not msg_ids:
                await asyncio.sleep(10)  # No messages, wait before checking again
                continue

            service = await get_user_service(email_address)
            malicious_label_id = get_or_create_malicious_label(service)

            #2. fetch full email content for batch
            batch_items = []
            valid_ids = []
            for mid in msg_ids:
                try:
                    email = service.users().messages().get(userId="me", id=mid).execute()
                    urls = extract_all_uris(service, mid, email['payload'])

                    batch_items.append({
                        "text": email.get('snippet', ''),
                        "urls": urls
                    })
                    valid_ids.append(mid)
                except Exception as e:
                    print(f"❌ Failed to fetch email {mid} for {email_address}: {e}")
            if not batch_items:
                continue

            #3. call batch predict (stress reduction)
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://xlmr_service:8001/predict_batch",
                    json={"items": batch_items},
                    timeout=45.0
                )
                results = response.json()

            #4. take action based on batch results
            for mid, res in zip(msg_ids, results):
                if res["label"] == "phishing":
                    print(f"🚨 PHISHING DETECTED in {mid}. Reason: {res.get('reason')}")
                    move_to_malicious(service, mid, malicious_label_id)
                    print(f"🚨 Moved {mid} to Malicious folder.")
                else:
                    print(f"✅ Message {mid} is safe.")
        except Exception as e:
            print(f"❌ Worker error for {email_address}: {e}")
            await asyncio.sleep(5)


@app.get("/login")
async def login():
    # Use the credentials.json to create an OAuth flow
    flow = Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline')
    return {"auth_url": auth_url}

@app.get("/callback")
async def oauth_callback(code: str):
    flow = Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(code=code)
    creds = flow.credentials

    # FIX: Decode the ID token to get the email dictionary
    try:
        # verify_oauth2_token decodes the JWT string into a dictionary
        id_info = id_token.verify_oauth2_token(
            creds.id_token, 
            requests.Request(), 
            CLIENT_CONFIG['web']['client_id']
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
    
    return RedirectResponse(url=f"{BASE_URL}/")
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return html_content

@app.post("/api/message")
async def api_submit_message(message: str = Form(...)):
    print(f"Received message: {message}")
    label, confidence = await classify_text(message)
    print(f"Label: {label}, Confidence: {confidence:.2%}")
    
    return JSONResponse({
        "status": "success",
        "label": label,
        "confidence": confidence,
        "message": message
    })

@app.post("/api/classify-email")
async def classify_email(request: EmailRequest):
    label, confidence = await classify_text(request.email)

    return {
        "email": request.email,
        "verdict": label,
        "confidence_percentage": round(confidence * 100, 2)
    }

@app.post("/analyze-full")
async def proxy_analyze_full(req: EmailRequest):
    async with httpx.AsyncClient() as client:
        # Forward the request to the internal xlmr_service
        explainer_service_url = os.getenv("EXPLAINER_URL", "http://xlmr_service:8001/analyze-full")
        response = await client.post(explainer_service_url, json={"text": req.email}, timeout=20.0)
        return response.json()

# ======================
# RUN SERVER
# ======================
if __name__ == "__main__":
    uvicorn.run("gmail:app", host="0.0.0.0", port=8002)
