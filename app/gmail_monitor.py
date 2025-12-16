import os
import pickle
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64
from email.mime.text import MIMEText
import time
from datetime import datetime

# If modifying these scopes, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    """Authenticate and return Gmail API service"""
    creds = None
    
    # The file token.pickle stores the user's access and refresh tokens
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    
    # If there are no (valid) credentials available, let the user log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    
    service = build('gmail', 'v1', credentials=creds)
    return service

def get_message_details(service, msg_id):
    """Get full message details including body"""
    try:
        message = service.users().messages().get(
            userId='me', 
            id=msg_id,
            format='full'
        ).execute()
        
        # Extract headers
        headers = message['payload']['headers']
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
        from_email = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
        date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown')
        
        # Extract body
        body = ""
        if 'parts' in message['payload']:
            for part in message['payload']['parts']:
                if part['mimeType'] == 'text/plain':
                    if 'data' in part['body']:
                        body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                        break
                elif part['mimeType'] == 'text/html' and not body:
                    # Fallback to HTML if no plain text
                    if 'data' in part['body']:
                        body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
        else:
            if 'body' in message['payload'] and 'data' in message['payload']['body']:
                body = base64.urlsafe_b64decode(message['payload']['body']['data']).decode('utf-8')
        
        return {
            'id': msg_id,
            'subject': subject,
            'from': from_email,
            'date': date,
            'body': body
        }
    except Exception as e:
        print(f"Error getting message details: {e}")
        return None

def print_message(msg_details, is_new=True):
    """Print message in a nice format"""
    print("\n" + "="*80)
    if is_new:
        print(f"📧 NEW MESSAGE RECEIVED")
    else:
        print(f"📬 RECENT UNREAD MESSAGE")
    print("="*80)
    print(f"From: {msg_details['from']}")
    print(f"Subject: {msg_details['subject']}")
    print(f"Date: {msg_details['date']}")
    print("-"*80)
    print("Message Body:")
    print(msg_details['body'][:1000])  # Print first 1000 characters
    if len(msg_details['body']) > 1000:
        print("... (truncated)")
    print("="*80 + "\n")

def get_recent_unread_messages(service, max_results=5):
    """Get recent unread messages"""
    try:
        results = service.users().messages().list(
            userId='me',
            maxResults=max_results,
            labelIds=['INBOX', 'UNREAD']
        ).execute()
        
        messages = results.get('messages', [])
        return messages
    except Exception as e:
        print(f"Error fetching unread messages: {e}")
        return []

def monitor_gmail(check_interval=10):
    """Monitor Gmail for new messages"""
    print("🚀 Starting Gmail Monitor...")
    print(f"⏰ Checking every {check_interval} seconds")
    print("Press Ctrl+C to stop\n")
    
    service = authenticate_gmail()
    
    # Show recent unread messages on startup
    print("📥 Fetching recent unread messages...\n")
    unread_messages = get_recent_unread_messages(service, max_results=5)
    
    if unread_messages:
        print(f"Found {len(unread_messages)} unread message(s):\n")
        for msg in unread_messages:
            msg_details = get_message_details(service, msg['id'])
            if msg_details:
                print_message(msg_details, is_new=False)
        last_message_id = unread_messages[0]['id']
    else:
        print("📭 No unread messages found.\n")
        # Get the most recent message to start monitoring
        try:
            results = service.users().messages().list(
                userId='me',
                maxResults=1,
                labelIds=['INBOX']
            ).execute()
            
            if 'messages' in results:
                last_message_id = results['messages'][0]['id']
        except Exception as e:
            print(f"Error initializing: {e}")
            return
    
    print("✅ Now monitoring for new messages...\n")
    
    while True:
        try:
            # Get the most recent message
            results = service.users().messages().list(
                userId='me',
                maxResults=1,
                labelIds=['INBOX']
            ).execute()
            
            if 'messages' in results:
                current_message_id = results['messages'][0]['id']
                
                # Check if there's a new message
                if current_message_id != last_message_id:
                    msg_details = get_message_details(service, current_message_id)
                    if msg_details:
                        print_message(msg_details, is_new=True)
                    last_message_id = current_message_id
            
            time.sleep(check_interval)
            
        except KeyboardInterrupt:
            print("\n\n👋 Stopping Gmail Monitor...")
            break
        except Exception as e:
            print(f"Error checking messages: {e}")
            time.sleep(check_interval)

if __name__ == "__main__":
    # You can change the check interval (in seconds)
    monitor_gmail(check_interval=10)