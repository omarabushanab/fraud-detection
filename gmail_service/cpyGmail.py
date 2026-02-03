import asyncio
import base64
import json
import os
import pickle
from urllib import response
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

BASE_URL = os.getenv("BASE_URL", "https://gus-hypertonic-otto.ngrok-free.dev")
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
    message_id: str = None
    user_email: str = None

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
# HISTORY TRACKING
# ======================

async def get_last_history_id(email: str) -> str:
    """Get the last processed historyId for a user"""
    history_id = await db.get(f"history:{email}")
    return history_id

async def update_last_history_id(email: str, history_id: str):
    """Update the last processed historyId for a user"""
    await db.set(f"history:{email}", history_id)
    print(f"📊 Updated history checkpoint for {email}: {history_id}")

async def get_current_history_id(service) -> str:
    """Get the current historyId from Gmail"""
    try:
        profile = service.users().getProfile(userId='me').execute()
        return profile.get('historyId')
    except Exception as e:
        print(f"Error getting current historyId: {e}")
        return None

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

async def scan_attachment_service(filename, raw_data):
    ATTACHMENT_SERVICE_URL = "http://attachment_service:8004/scan"
    async with httpx.AsyncClient() as client:
        try:
            files = {'file': (filename, raw_data)}
            response = await client.post(ATTACHMENT_SERVICE_URL, files=files, timeout=30.0)
            return response.json()
        except Exception as e:
            print(f"Connection error to attachment service: {e}")
            return {"is_malicious": False}
        
async def get_email_content_for_llm(payload):
    for part in payload.get('parts', []):
        if part.get('mimeType') == 'text/html':
            data = part['body'].get('data')
            if data:
                return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
    return None

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
                                pdf_document = fitz.open(stream=raw_data, filetype="pdf")
                                pdf_text = ""
                                for page_num in range(len(pdf_document)):
                                    page = pdf_document[page_num]
                                    pdf_text += page.get_text()
                                
                                if pdf_text.strip():
                                    parts_to_classify.append(pdf_text)
                                    print(f"✅ Extracted {len(pdf_text)} chars from PDF")
                                else:
                                    print(f"⚠️ PDF appears empty or has no extractable text")
                                    
                            except Exception as e:
                                print(f"❌ PDF extraction failed: {e}")
                        else:
                            # For non-PDF attachments, decode as text
                            try:
                                text = raw_data.decode('utf-8', errors='ignore')
                                parts_to_classify.append(text)
                            except Exception as e:
                                print(f"⚠️ Could not decode attachment {filename}: {e}")
                
                # Check nested parts
                if 'parts' in part:
                    walk_parts(part['parts'])
        
        # Start the recursive walk
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

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: Recover any abandoned tasks from 'task_in_progress' back to the queue
    Shutdown: (optional) flush tasks
    """
    print("♻️ Recovering abandoned tasks...")
    try:
        while True:
            # FIXED: Remove the extra await - lpop already returns the value
            task_raw = await db.lpop("task_in_progress")
            if not task_raw:
                break
            # Push it back to the main queue
            await db.lpush("global_task_queue", task_raw)
    except Exception as e:
        print(f"⚠️ Error recovering tasks: {e}")
    
    # Start background workers
    asyncio.create_task(global_sync_worker())
    asyncio.create_task(global_processing_worker())
    
    yield
    # Shutdown logic (if needed)

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/gmail/push")
async def gmail_push(request: Request):
    """
    Gmail Pub/Sub push endpoint.
    Decode the Pub/Sub message, identify the user's email,
    and queue messages for processing.
    """
    try:
        body = await request.json()
        message = body.get("message", {})
        data_b64 = message.get("data", "")
        
        if not data_b64:
            return {"status": "no data"}

        # Decode the Pub/Sub payload
        decoded = base64.b64decode(data_b64).decode("utf-8")
        notification = json.loads(decoded)
        email_address = notification.get("emailAddress")
        history_id = notification.get("historyId")

        print(f"📬 Pub/Sub notification for {email_address}, historyId={history_id}")

        # Add to sync queue
        await db.lpush(
            "global_sync_queue",
            json.dumps({"email": email_address, "history_id": history_id})
        )

        return {"status": "queued"}
    except Exception as e:
        print(f"Error in /gmail/push: {e}")
        return {"status": "error", "message": str(e)}


async def global_sync_worker():
    """
    Continuously pull from 'global_sync_queue' and fetch new messages.
    For each new message, add it to 'global_task_queue' for processing.
    """
    print("🚀 Global Sync Worker started.")
    while True:
        try:
            # FIXED: brpop returns a tuple (key, value) when successful, None when timeout
            result = await db.brpop("global_sync_queue", timeout=5)
            if not result:
                await asyncio.sleep(1)
                continue
            
            # Unpack the tuple
            _, sync_raw = result
            sync_data = json.loads(sync_raw)
            email = sync_data["email"]
            new_history_id = sync_data["history_id"]

            service = await get_user_service(email)
            if not service:
                print(f"⚠️ No service available for {email}")
                continue

            # Get the last processed historyId
            last_history_id = await get_last_history_id(email)
            
            if not last_history_id:
                # First time for this user - get current historyId and use it as baseline
                current_id = await get_current_history_id(service)
                if current_id:
                    await update_last_history_id(email, current_id)
                    last_history_id = current_id
                    print(f"🆕 First sync for {email}, baseline historyId: {current_id}")
                else:
                    # Fallback: do a full sync of recent messages
                    print(f"⚠️ Could not get historyId for {email}, doing full sync...")
                    try:
                        results = service.users().messages().list(
                            userId="me",
                            maxResults=10,
                            labelIds=["INBOX"]
                        ).execute()
                        messages = results.get("messages", [])
                        for msg in messages:
                            await db.lpush(
                                "global_task_queue",
                                json.dumps({"email": email, "msg_id": msg["id"]})
                            )
                        # Update to new historyId
                        await update_last_history_id(email, new_history_id)
                    except Exception as e:
                        print(f"Error in full sync: {e}")
                    continue

            # Fetch new messages using history API
            try:
                print(f"📨 Fetching history from {last_history_id} to {new_history_id} for {email}")
                history = service.users().history().list(
                    userId="me",
                    startHistoryId=last_history_id,
                    historyTypes=["messageAdded"]
                ).execute()

                message_count = 0
                for record in history.get("history", []):
                    for added in record.get("messagesAdded", []):
                        msg_id = added["message"]["id"]
                        # Queue this message for processing
                        await db.lpush(
                            "global_task_queue",
                            json.dumps({"email": email, "msg_id": msg_id})
                        )
                        message_count += 1
                
                if message_count > 0:
                    print(f"✅ Queued {message_count} new message(s) for {email}")
                
                # CRITICAL: Update the history checkpoint to the new historyId
                await update_last_history_id(email, new_history_id)

            except HttpError as e:
                if e.resp.status == 404:
                    print(f"⚠️ History not found for {email} (historyId too old), doing full sync...")
                    # Fallback to listing recent messages
                    results = service.users().messages().list(
                        userId="me",
                        maxResults=10,
                        labelIds=["INBOX"]
                    ).execute()
                    messages = results.get("messages", [])
                    for msg in messages:
                        await db.lpush(
                            "global_task_queue",
                            json.dumps({"email": email, "msg_id": msg["id"]})
                        )
                    # Update to new historyId
                    await update_last_history_id(email, new_history_id)
                else:
                    print(f"❌ HTTP Error {e.resp.status} fetching history: {e}")

        except Exception as e:
            print(f"❌ Global Sync Error: {e}")
            import traceback
            traceback.print_exc()
            await asyncio.sleep(5)


async def global_processing_worker():
    """
    A single worker that processes batches for ALL users.
    """
    print("🚀 Global Processing Worker started.")
    while True:
        try:
            tasks = []
            # Batch up to 8 tasks
            for _ in range(8):
                # FIXED: brpoplpush returns the value directly (a string), not a tuple
                t = await db.brpoplpush("global_task_queue", "task_in_progress", timeout=1)
                if t: 
                    tasks.append(t)
                else:
                    break
            
            if not tasks:
                await asyncio.sleep(5)
                continue

            work_by_user = {}
            for t_raw in tasks:
                data = json.loads(t_raw)
                work_by_user.setdefault(data["email"], []).append({"raw": t_raw, "id": data["msg_id"]})

            for email, msg_list in work_by_user.items():
                service = await get_user_service(email)
                if not service: 
                    # Remove from in_progress if no service available
                    for item in msg_list:
                        await db.lrem("task_in_progress", 1, item["raw"])
                    continue
                
                malicious_label_id = get_or_create_malicious_label(service)
                batch_items = []
                valid_mids = []
                raw_task_map = {} 

                for item in msg_list:
                    mid = item["id"]
                    raw_task_map[mid] = item["raw"]
                    try:
                        msg_details = service.users().messages().get(userId="me", id=mid).execute()
                        payload = msg_details['payload']

                        # Inside your worker loop
                        is_malicious_att = False
                        final_scan_res = {}
                        found_malicious_part = None # Use a clearer name

                        async def scan_parts(parts):
                            nonlocal is_malicious_att, final_scan_res
                            for part in parts:
                                if part.get('filename') and 'attachmentId' in part['body']:
                                    # Use to_thread to keep the loop from blocking on .execute()
                                    att = await asyncio.to_thread(service.users().messages().attachments().get(
                                        userId='me', messageId=mid, id=part['body']['attachmentId']
                                    ).execute)

                                    raw_data = base64.urlsafe_b64decode(att['data'])
                                    scan_res = await scan_attachment_service(part['filename'], raw_data)
                                    
                                    if scan_res.get("is_malicious"):
                                        final_scan_res = scan_res # Store results for triggers later
                                        is_malicious_att = True
                                        return part # SUCCESS: Return the malicious part object
                                
                                # Check nested parts recursively
                                if 'parts' in part: 
                                    result = await scan_parts(part['parts'])
                                    if result: return result # Bubble the result up the recursion
                            return None

                        if 'parts' in payload: 
                            found_malicious_part = await scan_parts(payload['parts'])

                        if is_malicious_att and found_malicious_part:
                            move_to_malicious(service, mid, malicious_label_id)
                            
                            storage_key = f"explanation:{email}:{mid}"
                            await db.setex(storage_key, 86400, json.dumps({
                                "label":"phishing",
                                "reason_type": "attachment",
                                "filename": found_malicious_part.get('filename'),
                                "reason": "Malicious attachment detected",
                                "triggers": final_scan_res.get("findings", [])
                            }))
                            await db.lrem("task_in_progress", 1, item["raw"])
                            print(f"🚨 Moved malicious attachment email {mid} for {email}")
                            continue
                        
                        email_html = await get_email_content_for_llm(payload)

                        # --- URL EXTRACTION ---
                        urls = extract_all_uris(service, mid, payload)
                        
                        batch_items.append({
                            "text": msg_details.get('snippet', ''),
                            "urls": urls,
                            "html": email_html                            
                        })
                        valid_mids.append(mid)

                    except Exception as e:
                        print(f"⚠️ Error fetching {mid}: {e}")
                        # Remove from in_progress on error
                        await db.lrem("task_in_progress", 1, item["raw"])

                # 3. Batch Predict
                if batch_items:
                    try:
                        async with httpx.AsyncClient() as client:
                            response = await client.post(
                                "http://xlmr_service:8001/predict_batch",
                                json={"items": batch_items},
                                timeout=45.0
                            )
                            if response.status_code != 200:
                                raise ValueError(f"Bad response from detector: {response.status_code}")
                                for mid in valid_mids:
                                    await db.lrem("task_in_progress", 1, raw_task_map[mid]) 
                                continue
                            results = response.json()

                        processed_count = 0
                        phishing_count = 0
                        for mid, res in zip(valid_mids, results):
                            if res["label"] == "phishing":
                                move_to_malicious(service, mid, malicious_label_id)
                                phishing_count += 1

                                explanation_data = {
                                    "label":"phishing",
                                    "reason_type": "xlmr" if "XLM-R" in res["reason"] else "llm",
                                    "reason": res["reason"],
                                    "confidence": res["confidence"],
                                    "malicious_url": res.get("url"),
                                    "triggers" : res.get("triggers", [])
                                    
                                }
                                if explanation_data["reason_type"] == "xlmr":
                                    try:
                                        async with httpx.AsyncClient() as client:
                                            explain_url = DETECTOR_SERVICE_URL.replace("/predict_batch", "/explain")
                                            explain_res = await client.post(
                                                explain_url,
                                                json={"text": batch_items[valid_mids.index(mid)]["text"]},
                                                timeout=20.0
            
                                            )
                                            explanation_data["triggers"] = explain_res.json().get("triggers", [])
                                    except Exception as e:
                                        print(f"⚠️ Explanation fetch error: {e}")
                                        explanation_data["triggers"] = []

                                await db.setex(f"explanation:{email}:{mid}", 86400, json.dumps(explanation_data))
                                
                            await db.lrem("task_in_progress", 1, raw_task_map[mid])
                            processed_count += 1
                        
                        print(f"✅ Processed {processed_count} emails for {email} ({phishing_count} phishing)")
                        
                    except Exception as e:
                        print(f"⚠️ Batch prediction error: {e}")
                        # Remove from in_progress on error
                        for mid in valid_mids:
                            await db.lrem("task_in_progress", 1, raw_task_map[mid])

        except Exception as e:
            print(f"❌ Global Processing Error: {e}")
            import traceback
            traceback.print_exc()
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
    watch_response = gmail_service.users().watch(
        userId='me', 
        body={'topicName': 'projects/unifonic-481420/topics/gmail-push'}
    ).execute()
    
    # CRITICAL: Store the initial historyId as the baseline
    initial_history_id = watch_response.get('historyId')
    if initial_history_id:
        await update_last_history_id(email, initial_history_id)
        print(f"🔖 Stored initial historyId for {email}: {initial_history_id}")
    
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

    if req.message_id and req.user_email:
        storage_key = f"explanation:{req.user_email}:{req.message_id}"
        cached_exp = await db.get(storage_key)
        if cached_exp:
            return json.loads(cached_exp)
        
        saved_scan = await db.get(f"scan_result:{req.message_id}")
        if saved_scan:
            scan_data = json.loads(saved_scan)
            if scan_data.get("is_malicious"):
                return {
                    "label": "phishing",
                    "reason_type": "attachment",
                    "filename": scan_data.get("filename"),
                    "reason": f"Malicious attachment: {scan_data.get('findings')}",
                    "triggers": scan_data.get("findings", [])
                }
    async with httpx.AsyncClient() as client:
        explainer_service_url = os.getenv("EXPLAINER_URL", "http://xlmr_service:8001/analyze-full")
        try:
            response = await client.post(explainer_service_url, json={"text": req.email}, timeout=20.0)
            return response.json()
        except Exception as e:
            print(f"XLM-R Service Error: {e}")
            return {
                "label": "safe",
                "reason_type": "error",
                "reason": "Could not analyze email",
                "triggers": []
            }

@app.get("/health")
def health():
    return {"status": "ok"}

# ======================
# RUN SERVER
# ======================
if __name__ == "__main__":
    uvicorn.run("gmail:app", host="0.0.0.0", port=8002)