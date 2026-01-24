import base64
import json
import os
import pickle
import fitz  # PyMuPDF
import io
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

def classify_text(text, found_uris):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = F.softmax(outputs.logits, dim=-1)

    idx = torch.argmax(probs, dim=-1).item()
    label = "Safe" if idx == 0 else "Malicious"
    confidence = probs[0][idx].item()

    return label, confidence

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


import re
from bs4 import BeautifulSoup

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
                    all_uris.add(a['href'])
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

                    # Use the msg_id to get the full message details from the service
                    message_details = service.users().messages().get(userId='me', id=msg_id).execute()

                    # Check the labels to see if 'SENT' is present
                    labels = message_details.get('labelIds', [])
                    print(f"📧 Processing message {msg_id} with labels: {labels}")

                    if 'INBOX' in labels:
                    
                        # Check the snippet first (fast check)
                        print(email.get('snippet', ''))
                        found_uris = extract_all_uris(service, msg_id, email['payload'])
                        label, conf = classify_text(email.get('snippet', ''), found_uris)
                        print(f"⚖️ Verdict for Mail Body: {label} ({conf:.2%})")
                        
                        if label == "Malicious":
                            is_malicious_found = True
                        else:
                            # Deep scan attachments (PDF and Text)
                            all_contents = get_parts_content(service, msg_id, email['payload'])
                            for item in all_contents:
                                if not item["content"].strip():
                                    continue
                                sawy = ""
                                label, conf = classify_text(item["content"], sawy)
                                print(f"⚖️ Verdict for {item['source']}: {label} ({conf:.2%})")

                                if label == "Malicious":
                                    is_malicious_found = True
                                    break

                        # 6. Take Action per User
                        if is_malicious_found:
                            move_to_malicious(service, msg_id, malicious_label_id)
                            print(f"🚨 ACTION: Moved {msg_id} for to Malicious folder.")
                        else:
                            print(f"✅ ACTION: Kept {msg_id} in Inbox.")

    except HttpError as error:
        # 404 means the History ID is too old (expires after 7 days)
        if error.resp.status == 404:
            print(f"⚠️ History ID expired for. Resetting baseline...")
        else:
            print(f"❌ API Error for: {error}")
    

    return {"status": "ok"}
# ======================
# RUN SERVER
# ======================
if __name__ == "__main__":
    get_gmail_service()
    uvicorn.run("gmail:app", host="0.0.0.0", port=8000)
