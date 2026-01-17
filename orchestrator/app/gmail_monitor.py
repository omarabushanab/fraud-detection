import base64
import json
import os
from google.oauth2 import service_account
from googleapiclient.discovery import build
from google.cloud import pubsub_v1
from .processor import clean_and_classify

# Use environment variables so you don't leak keys in code
PROJECT_ID = os.getenv("GOOGLE_PROJECT_ID", "unifonic-481420")
SUBSCRIPTION_ID = os.getenv("GMAIL_SUB_ID", "gmail-push-sub")
LABEL_NAME = 'malicious'

def get_gmail_service():
    # Looks for the file inside the Docker container
    creds = service_account.Credentials.from_service_account_file(
        'credentials.json', scopes=['https://www.googleapis.com/auth/gmail.modify']
    )
    return build('gmail', 'v1', credentials=creds)

def handle_new_email(msg_id):
    service = get_gmail_service()
    
    # Get email content
    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    body = ''
    if 'data' in msg['payload']['body']:
        body = base64.urlsafe_b64decode(msg['payload']['body']['data']).decode(errors='ignore')
    
    # Send to our processor bridge
    label, conf, urls = clean_and_classify(body)

    print(f"📧 Mail {msg_id}: Detected as {label} ({conf:.2%})")

    if label.lower() == "phishing" or label.lower() == "malicious":
        # Add logic here to move email to 'malicious' label
        print(f"🚨 ALERT: Moving {msg_id} to Malicious folder")

def callback(message):
    data = json.loads(base64.b64decode(message.data).decode())
    # Process history and call handle_new_email...
    # (Existing history logic from your original code goes here)
    message.ack()

def start_listener():
    subscriber = pubsub_v1.SubscriberClient()
    path = subscriber.subscription_path(PROJECT_ID, SUBSCRIPTION_ID)
    print("🚀 Orchestrator: Gmail Listener Active")
    streaming_pull_future = subscriber.subscribe(path, callback=callback)
    try:
        streaming_pull_future.result()
    except Exception as e:
        streaming_pull_future.cancel()

if __name__ == "__main__":
    start_listener()