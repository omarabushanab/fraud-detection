import re
import requests

class MailProcessor:
    def __init__(self, xlmr_url, url_analyzer_url):
        self.xlmr_url = xlmr_url
        self.url_analyzer_url = url_analyzer_url

    def process_email(self, raw_text):
        # 1. Extract URLs using Regex
        urls = re.findall(r'(https?://\S+)', raw_text)
        
        # 2. Analyze URLs (Call your URL module)
        url_results = []
        for url in urls:
            # Replace with your actual URL module endpoint
            res = requests.post(f"{self.url_analyzer_url}/analyze", json={"url": url})
            url_results.append(res.json())

        # 3. Replace URLs with placeholders for XLM-R
        # This is what you requested: "replace the URLs with placeholders"
        processed_text = re.sub(r'https?://\S+', '[URL]', raw_text)

        # 4. Get Phishing Prediction (Call your XLM-R service)
        xlmr_res = requests.post(f"{self.xlmr_url}/predict", json={"text": processed_text})
        
        return {
            "prediction": xlmr_res.json(),
            "url_analysis": url_results,
            "cleaned_text": processed_text
        }