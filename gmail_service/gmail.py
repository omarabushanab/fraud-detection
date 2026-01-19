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
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from fastapi.responses import HTMLResponse, JSONResponse




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

class EmailRequest(BaseModel):
    email: str

        
# HTML template embedded in the code
html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Fraud Detection AI</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            min-height: 100vh;
            background: #0a0e27;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }
        
        body::before {
            content: '';
            position: absolute;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle at 20% 50%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                        radial-gradient(circle at 80% 80%, rgba(74, 144, 226, 0.3) 0%, transparent 50%),
                        radial-gradient(circle at 40% 20%, rgba(138, 43, 226, 0.2) 0%, transparent 50%);
            animation: gradientShift 15s ease infinite;
        }
        
        @keyframes gradientShift {
            0%, 100% { transform: translate(0, 0) rotate(0deg); }
            33% { transform: translate(-5%, -5%) rotate(120deg); }
            66% { transform: translate(5%, 5%) rotate(240deg); }
        }
        
        .particles {
            position: absolute;
            width: 100%;
            height: 100%;
            overflow: hidden;
        }
        
        .particle {
            position: absolute;
            width: 3px;
            height: 3px;
            background: rgba(138, 180, 248, 0.6);
            border-radius: 50%;
            animation: particleFloat 20s linear infinite;
        }
        
        @keyframes particleFloat {
            0% {
                transform: translateY(100vh) translateX(0) scale(0);
                opacity: 0;
            }
            10% { opacity: 1; }
            90% { opacity: 1; }
            100% {
                transform: translateY(-100vh) translateX(100px) scale(1);
                opacity: 0;
            }
        }
        
        .grid-overlay {
            position: absolute;
            width: 100%;
            height: 100%;
            background-image: 
                linear-gradient(rgba(138, 180, 248, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(138, 180, 248, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            animation: gridMove 20s linear infinite;
        }
        
        @keyframes gridMove {
            0% { transform: translate(0, 0); }
            100% { transform: translate(50px, 50px); }
        }
        
        .container {
            background: rgba(15, 23, 42, 0.7);
            backdrop-filter: blur(20px) saturate(180%);
            padding: 60px 50px;
            border-radius: 32px;
            box-shadow: 
                0 0 80px rgba(138, 180, 248, 0.1),
                0 0 40px rgba(74, 144, 226, 0.1),
                inset 0 0 60px rgba(138, 180, 248, 0.02);
            max-width: 700px;
            width: 100%;
            position: relative;
            z-index: 1;
            animation: containerAppear 1s cubic-bezier(0.16, 1, 0.3, 1);
            border: 1px solid rgba(138, 180, 248, 0.1);
        }
        
        @keyframes containerAppear {
            from {
                opacity: 0;
                transform: translateY(40px) scale(0.95);
                filter: blur(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
                filter: blur(0);
            }
        }
        
        .container::before,
        .container::after {
            content: '';
            position: absolute;
            width: 100px;
            height: 100px;
            border: 2px solid;
            border-radius: 16px;
            animation: glowPulse 3s ease-in-out infinite;
        }
        
        .container::before {
            top: -2px;
            left: -2px;
            border-color: transparent transparent rgba(138, 180, 248, 0.3) rgba(138, 180, 248, 0.3);
        }
        
        .container::after {
            bottom: -2px;
            right: -2px;
            border-color: rgba(74, 144, 226, 0.3) rgba(74, 144, 226, 0.3) transparent transparent;
            animation-delay: 1.5s;
        }
        
        @keyframes glowPulse {
            0%, 100% { opacity: 0.3; filter: blur(0); }
            50% { opacity: 0.8; filter: blur(4px); }
        }
        
        .header-section {
            text-align: center;
            margin-bottom: 45px;
            position: relative;
        }
        
        .icon-shield {
            font-size: 64px;
            margin-bottom: 20px;
            display: inline-block;
            animation: shieldFloat 3s ease-in-out infinite;
            filter: drop-shadow(0 0 20px rgba(138, 180, 248, 0.5));
        }
        
        @keyframes shieldFloat {
            0%, 100% { transform: translateY(0) rotate(0deg); }
            50% { transform: translateY(-10px) rotate(5deg); }
        }
        
        h1 {
            color: #fff;
            margin-bottom: 12px;
            font-size: 42px;
            font-weight: 800;
            background: linear-gradient(135deg, #8AB4F8 0%, #4A90E2 50%, #7B68EE 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.5px;
            animation: titleShine 3s ease-in-out infinite;
        }
        
        @keyframes titleShine {
            0%, 100% { filter: brightness(1); }
            50% { filter: brightness(1.2); }
        }
        
        .subtitle {
            color: rgba(138, 180, 248, 0.7);
            font-size: 15px;
            font-weight: 500;
            letter-spacing: 0.5px;
        }
        
        .form-group {
            margin-bottom: 30px;
            position: relative;
        }
        
        label {
            display: block;
            margin-bottom: 12px;
            color: rgba(255, 255, 255, 0.9);
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
        }
        
        textarea {
            width: 100%;
            padding: 20px;
            border: 2px solid rgba(138, 180, 248, 0.2);
            border-radius: 16px;
            font-size: 16px;
            font-family: 'SF Mono', 'Monaco', 'Courier New', monospace;
            min-height: 180px;
            resize: vertical;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            background: rgba(15, 23, 42, 0.5);
            color: #fff;
            box-shadow: inset 0 2px 10px rgba(0, 0, 0, 0.3);
        }
        
        textarea:focus {
            outline: none;
            border-color: rgba(138, 180, 248, 0.6);
            background: rgba(15, 23, 42, 0.8);
            box-shadow: 
                inset 0 2px 10px rgba(0, 0, 0, 0.3),
                0 0 0 4px rgba(138, 180, 248, 0.1),
                0 0 30px rgba(138, 180, 248, 0.2);
            transform: translateY(-2px);
        }
        
        textarea::placeholder {
            color: rgba(138, 180, 248, 0.3);
        }
        
        button {
            background: linear-gradient(135deg, #8AB4F8 0%, #4A90E2 50%, #7B68EE 100%);
            color: white;
            padding: 18px 40px;
            border: none;
            border-radius: 16px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 700;
            width: 100%;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 
                0 10px 30px rgba(138, 180, 248, 0.3),
                0 0 0 0 rgba(138, 180, 248, 0.5);
            text-transform: uppercase;
            letter-spacing: 2px;
            position: relative;
            overflow: hidden;
        }
        
        button::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.3);
            transform: translate(-50%, -50%);
            transition: width 0.6s, height 0.6s;
        }
        
        button:hover::before {
            width: 300px;
            height: 300px;
        }
        
        button:hover {
            transform: translateY(-3px) scale(1.02);
            box-shadow: 
                0 15px 40px rgba(138, 180, 248, 0.4),
                0 0 60px rgba(138, 180, 248, 0.3);
        }
        
        button:active {
            transform: translateY(-1px) scale(0.98);
        }
        
        button span {
            position: relative;
            z-index: 1;
        }
        
        .spinner {
            display: none;
            width: 24px;
            height: 24px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .loading .spinner {
            display: block;
        }
        
        .loading span {
            display: none;
        }
        
        .status-bar {
            display: flex;
            gap: 8px;
            justify-content: center;
            margin-top: 25px;
            opacity: 0.6;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: rgba(138, 180, 248, 0.3);
            animation: statusPulse 2s ease-in-out infinite;
        }
        
        .status-dot:nth-child(2) { animation-delay: 0.2s; }
        .status-dot:nth-child(3) { animation-delay: 0.4s; }
        
        @keyframes statusPulse {
            0%, 100% { transform: scale(1); opacity: 0.3; }
            50% { transform: scale(1.2); opacity: 1; }
        }
        
        .scan-line {
            position: absolute;
            width: 100%;
            height: 2px;
            background: linear-gradient(90deg, 
                transparent 0%, 
                rgba(138, 180, 248, 0.5) 50%, 
                transparent 100%);
            animation: scan 3s ease-in-out infinite;
            pointer-events: none;
        }
        
        @keyframes scan {
            0%, 100% { top: 0%; opacity: 0; }
            50% { top: 100%; opacity: 1; }
        }

        /* Modal Overlay */
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.85);
            backdrop-filter: blur(10px);
            z-index: 1000;
            animation: fadeIn 0.3s ease;
        }
        
        .modal-overlay.active {
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        /* Result Modal */
        .result-modal {
            background: rgba(15, 23, 42, 0.95);
            backdrop-filter: blur(30px);
            border-radius: 32px;
            padding: 50px 45px;
            max-width: 500px;
            width: 90%;
            position: relative;
            border: 2px solid rgba(138, 180, 248, 0.2);
            box-shadow: 
                0 0 100px rgba(138, 180, 248, 0.2),
                inset 0 0 80px rgba(138, 180, 248, 0.03);
            animation: modalSlideIn 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
        }
        
        @keyframes modalSlideIn {
            from {
                opacity: 0;
                transform: scale(0.8) translateY(50px);
            }
            to {
                opacity: 1;
                transform: scale(1) translateY(0);
            }
        }
        
        .result-icon {
            font-size: 80px;
            text-align: center;
            margin-bottom: 25px;
            animation: iconPop 0.6s cubic-bezier(0.34, 1.56, 0.64, 1) 0.3s both;
        }
        
        @keyframes iconPop {
            0% {
                transform: scale(0) rotate(-180deg);
                opacity: 0;
            }
            100% {
                transform: scale(1) rotate(0deg);
                opacity: 1;
            }
        }
        
        .result-title {
            text-align: center;
            font-size: 32px;
            font-weight: 800;
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .result-title.safe {
            background: linear-gradient(135deg, #10b981 0%, #34d399 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .result-title.malicious {
            background: linear-gradient(135deg, #ef4444 0%, #f87171 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .confidence-container {
            margin: 30px 0;
            text-align: center;
        }
        
        .confidence-label {
            color: rgba(138, 180, 248, 0.7);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 15px;
            font-weight: 600;
        }
        
        .confidence-bar {
            width: 100%;
            height: 12px;
            background: rgba(138, 180, 248, 0.1);
            border-radius: 20px;
            overflow: hidden;
            position: relative;
            margin-bottom: 12px;
        }
        
        .confidence-fill {
            height: 100%;
            border-radius: 20px;
            transition: width 1s cubic-bezier(0.34, 1.56, 0.64, 1) 0.5s;
            position: relative;
            overflow: hidden;
        }
        
        .confidence-fill.safe {
            background: linear-gradient(90deg, #10b981, #34d399);
            box-shadow: 0 0 20px rgba(16, 185, 129, 0.5);
        }
        
        .confidence-fill.malicious {
            background: linear-gradient(90deg, #ef4444, #f87171);
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.5);
        }
        
        .confidence-fill::after {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            animation: shimmer 2s infinite;
        }
        
        @keyframes shimmer {
            to { left: 100%; }
        }
        
        .confidence-value {
            font-size: 36px;
            font-weight: 800;
            color: #fff;
            text-align: center;
        }
        
        .result-message {
            text-align: center;
            color: rgba(138, 180, 248, 0.8);
            font-size: 15px;
            line-height: 1.6;
            margin-bottom: 30px;
        }
        
        .close-btn {
            width: 100%;
            padding: 16px;
            background: rgba(138, 180, 248, 0.1);
            border: 2px solid rgba(138, 180, 248, 0.3);
            border-radius: 12px;
            color: #8AB4F8;
            font-weight: 700;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .close-btn:hover {
            background: rgba(138, 180, 248, 0.2);
            border-color: rgba(138, 180, 248, 0.5);
            transform: translateY(-2px);
        }
        
        /* Pulse animation for modal background */
        .result-modal::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle, rgba(138, 180, 248, 0.1) 0%, transparent 70%);
            transform: translate(-50%, -50%);
            animation: pulse 3s ease-in-out infinite;
            pointer-events: none;
        }
        
        @keyframes pulse {
            0%, 100% { transform: translate(-50%, -50%) scale(1); opacity: 0.5; }
            50% { transform: translate(-50%, -50%) scale(1.1); opacity: 0.8; }
        }
        
        .modal-content {
            position: relative;
            z-index: 1;
        }
    </style>
</head>
<body>
    <div class="particles">
        <div class="particle" style="left: 10%; animation-delay: 0s;"></div>
        <div class="particle" style="left: 20%; animation-delay: 2s;"></div>
        <div class="particle" style="left: 30%; animation-delay: 4s;"></div>
        <div class="particle" style="left: 40%; animation-delay: 1s;"></div>
        <div class="particle" style="left: 50%; animation-delay: 3s;"></div>
        <div class="particle" style="left: 60%; animation-delay: 5s;"></div>
        <div class="particle" style="left: 70%; animation-delay: 2s;"></div>
        <div class="particle" style="left: 80%; animation-delay: 4s;"></div>
        <div class="particle" style="left: 90%; animation-delay: 1s;"></div>
    </div>
    
    <div class="grid-overlay"></div>
    
    <div class="container">
        <div class="scan-line"></div>
        
        <div class="header-section">
            <div class="icon-shield">🛡️</div>
            <h1>FRAUD DETECTION AI</h1>
            <p class="subtitle">Advanced Neural Network Analysis</p>
        </div>
        
        <form id="messageForm">
            <div class="form-group">
                <label>ANALYZE MESSAGE</label>
                <textarea 
                    id="message" 
                    name="message" 
                    placeholder="Paste suspicious message for AI-powered fraud detection..." 
                    required
                ></textarea>
            </div>
            <button type="submit" id="submitBtn">
                <span>INITIATE SCAN</span>
                <div class="spinner"></div>
            </button>
        </form>
        
        <div class="status-bar">
            <div class="status-dot"></div>
            <div class="status-dot"></div>
            <div class="status-dot"></div>
        </div>
    </div>
    
    <!-- Result Modal -->
    <div class="modal-overlay" id="resultModal">
        <div class="result-modal">
            <div class="modal-content">
                <div class="result-icon" id="resultIcon"></div>
                <div class="result-title" id="resultTitle"></div>
                
                <div class="confidence-container">
                    <div class="confidence-label">Confidence Score</div>
                    <div class="confidence-bar">
                        <div class="confidence-fill" id="confidenceFill"></div>
                    </div>
                    <div class="confidence-value" id="confidenceValue"></div>
                </div>
                
                <div class="result-message" id="resultMessage"></div>
                
                <button class="close-btn" onclick="closeModal()">Close</button>
            </div>
        </div>
    </div>
    
    <script>
        function closeModal() {
            document.getElementById('resultModal').classList.remove('active');
        }
        
        function showResult(label, confidence) {
            const modal = document.getElementById('resultModal');
            const icon = document.getElementById('resultIcon');
            const title = document.getElementById('resultTitle');
            const fill = document.getElementById('confidenceFill');
            const value = document.getElementById('confidenceValue');
            const message = document.getElementById('resultMessage');
            
            const isSafe = label.toLowerCase() === 'safe';
            const confidencePercent = (confidence * 100).toFixed(1);
            
            // Set icon and title
            icon.textContent = isSafe ? '✅' : '⚠️';
            title.textContent = label.toUpperCase();
            title.className = `result-title ${isSafe ? 'safe' : 'malicious'}`;
            
            // Set confidence bar
            fill.className = `confidence-fill ${isSafe ? 'safe' : 'malicious'}`;
            setTimeout(() => {
                fill.style.width = confidencePercent + '%';
            }, 100);
            
            // Set confidence value
            value.textContent = confidencePercent + '%';
            
            // Set message
            if (isSafe) {
                message.textContent = 'Our AI analysis indicates this message is legitimate. However, always exercise caution with sensitive information.';
            } else {
                message.textContent = 'ALERT: This message shows characteristics of fraud or phishing. Do not click any links or provide personal information.';
            }
            
            // Show modal
            modal.classList.add('active');
        }
        
        document.getElementById('messageForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const message = document.getElementById('message').value;
            const submitBtn = document.getElementById('submitBtn');
            const formData = new FormData();
            formData.append('message', message);
            
            submitBtn.classList.add('loading');
            
            try {
                const response = await fetch('/api/message', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                setTimeout(() => {
                    submitBtn.classList.remove('loading');
                    document.getElementById('message').value = '';
                    
                    // Show result modal
                    showResult(data.label, data.confidence);
                }, 1500);
                
            } catch (error) {
                submitBtn.classList.remove('loading');
                alert('Error analyzing message. Please try again.');
            }
        });
        
        // Close modal when clicking outside
        document.getElementById('resultModal').addEventListener('click', (e) => {
            if (e.target.id === 'resultModal') {
                closeModal();
            }
        });
    </script>
    <div class="subscription-section" style="margin-top: 30px; border-top: 1px solid rgba(138, 180, 248, 0.1); padding-top: 20px;">
    <button onclick="startSubscription()" id="subBtn" style="background: linear-gradient(135deg, #10b981 0%, #34d399 100%);">
        <span>CONNECT NEW GMAIL INBOX</span>
    </button>
    <p id="subStatus" style="color: rgba(138, 180, 248, 0.7); font-size: 12px; margin-top: 10px;"></p>
</div>

<script>
async function startSubscription() {
    const btn = document.getElementById('subBtn');
    const status = document.getElementById('subStatus');
    
    try {
        // Step 1: Call your backend to get the Google Auth URL
        const response = await fetch('https://jonell-ardeid-interpervasively.ngrok-free.dev/login');
        const data = await response.json();
        
        if (data.auth_url) {
            status.textContent = "Redirecting to Google...";
            // Step 2: Redirect user to Google's consent screen
            window.location.href = data.auth_url;
        }
    } catch (error) {
        status.textContent = "Error starting subscription. Please check console.";
        console.error(error);
    }
}
</script>
</body>
</html>
"""


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

# ======================
# RUN SERVER
# ======================
if __name__ == "__main__":
    uvicorn.run("gmail:app", host="0.0.0.0", port=8002)
