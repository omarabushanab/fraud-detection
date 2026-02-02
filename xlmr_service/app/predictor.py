import asyncio
from email.mime import text
import torch
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import os
import shap 
from urlextract import URLExtract
import httpx
from google import genai
import json
from app.utils import clean_html_for_llm, is_mostly_html

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
os.environ["TRANSFORMERS_OFFLINE"] = "1"
    
CLASSIFIER_SERVICE_URL = os.getenv("CLASSIFIER_URL", "http://classifier_service:8003/classify_url")

# Performance settings
GEMINI_ENABLED = os.getenv("GEMINI_ENABLED", "true").lower() == "true"
GEMINI_TIMEOUT = int(os.getenv("GEMINI_TIMEOUT", "10"))  # 10 second timeout for Gemini


class XLMRPredictor:
    def __init__(self, model_path):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        self.tokenizer = AutoTokenizer.from_pretrained(model_path, use_fast=False)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path, local_files_only=True)
        self.model.to(self.device)
        self.model.eval()
        self.explainer_pipeline = pipeline(
            "text-classification", 
            model=self.model, 
            tokenizer=self.tokenizer, 
            device=self.device,
            top_k=None
        )
        self.explainer = shap.Explainer(self.explainer_pipeline)

    def explain(self, text):
            """Extract SHAP-based triggers from text (Top 5 contributors)"""
            try:
                shap_values = self.explainer([text])
                tokens = shap_values.data[0]
                values = shap_values.values[0][:, 1]  # Contribution to 'Phishing' class
                
                token_val_pairs = []
                
                # XLM-R uses U+2581 ( ) as the space marker. 
                # We must use that specific unicode character in the replace() call.
                sentence_piece_marker = '\u2581' 
                
                for i, val in enumerate(values):
                    # Clean the token: remove the marker and whitespace
                    clean_t = tokens[i].replace(sentence_piece_marker, '').strip()
                    
                    # Filter: Only positive contributions and meaningful words (>2 chars)
                    if val > 0 and len(clean_t) > 2:
                        token_val_pairs.append((val, clean_t))
                
                # Sort by impact (highest first) and take top 5
                token_val_pairs.sort(key=lambda x: x[0], reverse=True)
                
                # Extract just the words
                triggers = [pair[1] for pair in token_val_pairs[:5]]
                
                print(f"🔍 SHAP Triggers found: {triggers}")
                return list(set(triggers))
                
            except Exception as e:
                print(f"SHAP explanation error: {e}")
                return []
    async def predict(self, text: str, urls: list[str] = [], raw_html: str = None):
        """
        Single email prediction with optimized Gemini usage.
        Gemini is only called for very HTML-heavy content or uncertain cases.
        """
        # 1. Check URLs first (fast)
        # 1. Check URLs first (fast) using ONE client (connection pooling)
        async with httpx.AsyncClient() as http_client:
            for u in urls:
                try:
                    response = await http_client.post(
                        CLASSIFIER_SERVICE_URL,
                        json={"url": u},
                        timeout=5.0
                    )
                    data = response.json()
                    if data.get("prediction") == "PHISHING":
                        return {
                            "url": u,
                            "label": "phishing",
                            "confidence": data.get("probability", 1.0),
                            "reason": "Malicious URL"
                        }
                except Exception as e:
                    print(f"URL Classifier error: {e}")

        # 2. Check if content is VERY HTML-heavy (threshold raised to 70%)
        # This reduces unnecessary Gemini calls
        print(f"🔍 Checking HTML heaviness...{raw_html} and {is_mostly_html(raw_html,text)}")
        if GEMINI_ENABLED and (is_mostly_html(raw_html, text)):
            print("🔍 Content is >70% HTML. Escalating to Gemini...")
            try:
                result = await self.call_gemini_verdict(
                    clean_html_for_llm(raw_html),
                    timeout=GEMINI_TIMEOUT
                )
                return result
            except Exception as e:
                print(f"Gemini failed, falling back to XLM-R: {e}")
                # Continue to XLM-R

        # 3. Use XLM-R for standard text (fast)
        print("🔍 Analyzing with XLM-R Model...")
        inputs = self.tokenizer(
            text, 
            return_tensors="pt", 
            truncation=True, 
            padding=True, 
            max_length=512
        ).to(self.device)
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)

        phishing_prob = probs[0][1].item()

        # 4. Handle "gray zone" ONLY if Gemini is enabled and we have HTML
        # Narrowed the gray zone to 0.45-0.65 to reduce Gemini calls
        print(f"🔍 line 117 Checking HTML heaviness...{raw_html} and {is_mostly_html(raw_html,text)}")
        
        if GEMINI_ENABLED and (0.45 < phishing_prob < 0.65 or raw_html):
            print(f"🤔 XLM-R uncertain (p={phishing_prob:.2f}). Trying Gemini...")
            try:
                result = await self.call_gemini_verdict(
                    clean_html_for_llm(raw_html),
                    timeout=GEMINI_TIMEOUT
                )
                return result
            except Exception as e:
                print(f"Gemini timeout/error, using XLM-R result: {e}")
                # Fall through to XLM-R result

        # 5. Return XLM-R result
        label = "phishing" if phishing_prob >= 0.5 else "safe"
        return {
            "label": label,
            "confidence": round(phishing_prob if label == "phishing" else probs[0][0].item(), 4),
            "reason": "Analyzed by XLM-R"
        }

    # predictor.py - Updated predict_batch
    async def predict_batch(self, items: list):
        """
        Batch prediction:
        1) URL check (fast)
        2) HTML-heavy -> Gemini (only for those items)
        3) XLM-R batch inference for the rest
        """
        results = [None] * len(items)

        url_or_done_indices = set()

        gemini_indices = []
        gemini_payloads = []

        ml_indices = []
        texts_to_ml = []

        async with httpx.AsyncClient() as client:
            # -------------------------
            # Phase 1: URL check
            # -------------------------
            for i, item in enumerate(items):
                # support both dict and pydantic
                text = item.text if hasattr(item, "text") else item.get("text", "")
                urls = item.urls if hasattr(item, "urls") else item.get("urls", [])
                raw_html = item.html if hasattr(item, "html") else item.get("html", None)

                # URL check first
                found_url_phish = False
                for url in urls:
                    try:
                        resp = await client.post(
                            CLASSIFIER_SERVICE_URL,
                            json={"url": url},
                            timeout=5.0
                        )
                        data = resp.json()
                        if data.get("prediction") == "PHISHING":
                            results[i] = {
                                "label": "phishing",
                                "reason_type": "url",
                                "url": url,
                                "confidence": data.get("probability", 1.0),
                                "reason": "Malicious URL detected",
                                "triggers": []
                            }
                            found_url_phish = True
                            print(f"Item {i}: Malicious URL found: {url}")
                            break
                    except Exception:
                        continue

                if found_url_phish:
                    url_or_done_indices.add(i)
                    continue

                # -------------------------
                # Phase 2: HTML-heavy -> Gemini
                # -------------------------
                print(f"🔍 Checking HTML heaviness...{raw_html} and {is_mostly_html(raw_html,text)}")
                if GEMINI_ENABLED and (is_mostly_html(raw_html,text)):
                    print(f"Item {i}: Escalating to Gemini due to {'raw_html' if raw_html else 'HTML heaviness'}")
                    gemini_indices.append(i)
                    gemini_payloads.append(raw_html)
                    continue

                # -------------------------
                # Phase 3: send to XLM-R batch
                # -------------------------
                texts_to_ml.append(text)
                ml_indices.append(i)

            # -------------------------
            # Run Gemini for HTML-heavy items
            # -------------------------
            if gemini_indices:
                for idx, raw_html in zip(gemini_indices, gemini_payloads):
                    try:
                        verdict = await self.call_gemini_verdict(
                            clean_html_for_llm(raw_html),
                            timeout=GEMINI_TIMEOUT
                        )

                        # normalize response format
                        results[idx] = {
                            "label": verdict.get("label", "safe"),
                            "confidence": verdict.get("confidence", 0.0),
                            "reason_type": "llm",
                            "reason": verdict.get("reason", "LLM verdict"),
                            "url": None,
                            "triggers": []
                        }
                    except Exception as e:
                        # fallback to XLM-R if Gemini fails
                        text = items[idx].text if hasattr(items[idx], "text") else items[idx].get("text", "")
                        texts_to_ml.append(text)
                        ml_indices.append(idx)

            # -------------------------
            # XLM-R batch inference
            # -------------------------
            if texts_to_ml:
                inputs = self.tokenizer(
                    texts_to_ml,
                    return_tensors="pt",
                    truncation=True,
                    padding=True,
                    max_length=512
                ).to(self.device)

                with torch.no_grad():
                    probs = torch.softmax(self.model(**inputs).logits, dim=-1)

                for j, original_index in enumerate(ml_indices):
                    p_prob = probs[j][1].item()
                    label = "phishing" if p_prob >= 0.5 else "safe"

                    results[original_index] = {
                        "label": label,
                        "confidence": round(p_prob if label == "phishing" else probs[j][0].item(), 4),
                        "reason_type": "xlmr",
                        "reason": "Analyzed by XLM-R",
                        "url": None,
                        "triggers": []
                    }

        return results
    
    # async def call_gemini_verdict(self, text: str, timeout: int = 10):
    #     """
    #     Calls Gemini with timeout protection.
    #     """
    #     prompt = f"""
    #     Analyze the following email content for phishing or malicious intent. 
    #     Focus on social engineering, urgency, or suspicious links. 
    #     Promotional emails, newsletters, and receipts are SAFE.
        
    #     Content: {text[:4000]}
        
    #     Respond ONLY in valid JSON: {{"label": "phishing" | "safe", "confidence": 0.0-1.0, "reason": "why"}}
    #     """
    #     try:
    #         async with httpx.AsyncClient(timeout=timeout) as client:
    #             # Gemini API call wrapped in timeout
    #             response = client.models.generate_content(
    #                 model="gemini-2.5-flash-lite",
    #                 contents=prompt
    #             )
                
    #             # Parse response
    #             clean_json = response.text.replace('```json', '').replace('```', '').strip()
    #             result = json.loads(clean_json)
    #             result["reason"] = f"LLM: {result.get('reason', 'N/A')}"
                
    #             if "triggers" not in result:
    #                 result["triggers"] = []
                    
    #             return result
                
    #     except httpx.TimeoutException:
    #         print(f"⏱️ Gemini timeout after {timeout}s")
    #         raise
    #     except Exception as e:
    #         print(f"Gemini API Error: {e}")
    #         raise

    async def call_gemini_verdict(self, text: str, timeout: int = 10):
        """
        Calls Gemini safely without mixing httpx client with Gemini client.
        """
        prompt = f"""
        Analyze the following email content for phishing or malicious intent. 
        Focus on social engineering, urgency, or suspicious links. 
        Promotional emails, newsletters, and receipts are SAFE.

        Content: {text[:4000]}

        Respond ONLY in valid JSON: {{"label": "phishing" | "safe", "confidence": 0.0-1.0, "reason": "why"}}
        """

        try:
            # IMPORTANT:
            # This is the Gemini SDK client defined globally:
            # client = genai.Client(api_key=...)
            response = await asyncio.to_thread(
                client.models.generate_content,
                model="gemini-2.5-flash-lite",
                contents=prompt
            )

            clean_json = response.text.replace("```json", "").replace("```", "").strip()
            result = json.loads(clean_json)

            result["reason"] = f"LLM: {result.get('reason', 'N/A')}"
            if "triggers" not in result:
                result["triggers"] = []
            # In predictor.py inside call_gemini_verdict
            print(f"✨ Gemini Response Received: {result['label']} (Confidence: {result['confidence']})")
            return result

        except Exception as e:
            print(f"Gemini API Error: {e}")
            raise
