import re
import requests
import os

# Docker uses service names as hostnames. 
# 'xlmr-service' matches the name we will put in docker-compose.
XLMR_URL = os.getenv("XLMR_SERVICE_URL", "http://xlmr-service:8000")

def clean_and_classify(text):
    # 1. URL Placeholder logic (as per your project requirements)
    # Replaces 'https://link.com' with '[URL]'
    processed_text = re.sub(r'https?://\S+', '[URL]', text)

    # 2. Extract URLs to send to your URL module later
    urls = re.findall(r'https?://\S+', text)

    try:
        # 3. Network call to the XLM-R container
        response = requests.post(
            f"{XLMR_URL}/predict",
            json={"text": processed_text},
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        
        # Returns: Label (Safe/Phishing), Confidence, and the list of URLs found
        return data["label"], data["confidence"], urls
    except Exception as e:
        print(f"Error calling XLM-R service: {e}")
        return "Error", 0.0, urls