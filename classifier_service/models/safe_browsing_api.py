import os
import requests

GSB_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")
GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

import requests
import json

class SafeURLExpander:
    def __init__(self, api_key):
        self.api_key = api_key
        self.safe_browsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    def check_url_safety(self, url):
        """
        Check if URL is malicious using Google Safe Browsing.
        
        Returns:
            dict with 'is_safe' (bool) and 'threats' (list)
        """
        payload = {
            "client": {
                "clientId": "your-client-id",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", 
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }
        
        try:
            response = requests.post(
                f"{self.safe_browsing_url}?key={self.api_key}",
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                threats = result.get('matches', [])
                
                return {
                    'is_safe': len(threats) == 0,
                    'threats': threats,
                    'url': url
                }
            else:
                print(f"Safe Browsing API error: {response.status_code}")
                return {'is_safe': None, 'threats': [], 'url': url}
                
        except requests.RequestException as e:
            print(f"Error checking URL safety: {e}")
            return {'is_safe': None, 'threats': [], 'url': url}
    
    def safe_resolve_redirects(self, url, max_redirects=5, timeout=3):
        """
        Safely expand URL with Safe Browsing check before following redirects.
        
        Returns:
            dict with 'final_url', 'is_safe', and 'threats'
        """
        # First check if the original URL is safe
        safety_check = self.check_url_safety(url)
        
        if safety_check['is_safe'] == False:
            print(f"⚠️  Original URL is malicious: {url}")
            return {
                'final_url': None,
                'is_safe': False,
                'threats': safety_check['threats'],
                'original_url': url
            }
        
        # If safe (or unknown), try to expand
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            session = requests.Session()
            session.max_redirects = max_redirects
            
            response = session.head(
                url,
                allow_redirects=True,
                timeout=timeout,
                headers=headers
            )
            
            final_url = response.url
            
            # Check if final destination is safe
            final_safety = self.check_url_safety(final_url)
            
            if final_safety['is_safe'] == False:
                print(f"⚠️  Redirect leads to malicious URL: {final_url}")
                return {
                    'final_url': final_url,
                    'is_safe': False,
                    'threats': final_safety['threats'],
                    'original_url': url
                }
            
            return {
                'final_url': final_url,
                'is_safe': final_safety['is_safe'],
                'threats': final_safety['threats'],
                'original_url': url
            }
            
        except requests.TooManyRedirects:
            print(f"Too many redirects for {url}")
            return {
                'final_url': None,
                'is_safe': None,
                'threats': [],
                'original_url': url,
                'error': 'too_many_redirects'
            }
        except requests.Timeout:
            print(f"Timeout expanding {url}")
            return {
                'final_url': None,
                'is_safe': None,
                'threats': [],
                'original_url': url,
                'error': 'timeout'
            }
        except requests.RequestException as e:
            print(f"Failed to expand {url}: {e}")
            return {
                'final_url': None,
                'is_safe': None,
                'threats': [],
                'original_url': url,
                'error': str(e)
            }