import base64
import json
import pickle
import os

from google.oauth2 import service_account
from googleapiclient.discovery import build
from google.cloud import pubsub_v1

from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import torch.nn.functional as F


# =====================
# CONFIG
# =====================
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
SERVICE_ACCOUNT_FILE = 'credentials.json'
PROJECT_ID = 'unifonic-481420'
SUBSCRIPTION_ID = 'gmail-push-sub'
LABEL_NAME = 'malicious'


# =====================
# ML MODEL
# =====================
MODEL_PATH = r"G:\.shortcut-targets-by-id\1x507Fs2GpRNcZXoBsd7NiSFQv_6mQ200\xlm-r-phishing-final"

tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH, local_files_only=True)
model.eval()


def classify_text(text):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = F.softmax(outputs.logits, dim=-1)

    idx = torch.argmax(probs, dim=-1).item()
    return ("Safe", "Malicious")[idx], probs[0][idx].item()


# =====================
# GMAIL SERVICE
# =====================
def get_gmail_service():
    creds = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES
    )
    return build('gmail', 'v1', credentials=creds)


def get_or_create_label(service, name):
    labels = service.users().labels().list(userId='me').execute()['labels']
    for l in labels:
        if l['name'].lower() == name.lower():
            return l['id']

    return service.users().labels().create(
        userId='me',
        body={'name': name}
    ).execute()['id']


def move_to_malicious(service, msg_id, label_id):
    service.users().messages().modify(
        userId='me',
        id=msg_id,
        body={'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']}
    ).execute()


# =====================
# EMAIL HANDLING
# =====================
def handle_new_email(msg_id):
    service = get_gmail_service()
    label_id = get_or_create_label(service, LABEL_NAME)

    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

    headers = msg['payload']['headers']
    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')

    body = ''
    if 'data' in msg['payload']['body']:
        body = base64.urlsafe_b64decode(
            msg['payload']['body']['data']
        ).decode(errors='ignore')

    label, conf = classify_text(subject + "\n" + body)

    print(f"📧 {msg_id} → {label} ({conf:.2%})")

    if label == "Malicious":
        move_to_malicious(service, msg_id, label_id)
        print("🚨 Moved to MALICIOUS")


# =====================
# PUBSUB LISTENER
# =====================
def callback(message):
    data = json.loads(base64.b64decode(message.data).decode())
    history_id = data['historyId']

    service = get_gmail_service()
    history = service.users().history().list(
        userId='me',
        startHistoryId=history_id,
        historyTypes=['messageAdded']
    ).execute()

    for h in history.get('history', []):
        for msg in h.get('messagesAdded', []):
            handle_new_email(msg['message']['id'])

    message.ack()


def start_listener():
    subscriber = pubsub_v1.SubscriberClient()
    path = subscriber.subscription_path(PROJECT_ID, SUBSCRIPTION_ID)

    print("🚀 Real-time Gmail listener started")
    subscriber.subscribe(path, callback=callback)

    while True:
        pass


if __name__ == "__main__":
    start_listener()
