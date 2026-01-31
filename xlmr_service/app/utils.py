import re
from bs4 import BeautifulSoup

def clean_html_for_llm(html_content):
    """Removes noise and returns clean text for the LLM."""
    if not html_content:
        return ""
    
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Remove non-content tags
    for element in soup(['script', 'style', 'nav', 'footer', 'header', 'aside']):
        element.decompose()
        
    # Extract text with whitespace normalization
    text = soup.get_text(separator=' ')
    clean_text = re.sub(r'\s+', ' ', text).strip()
    return clean_text

# def is_mostly_html(raw_content, threshold=0.10):
#     """
#     Detects if content is HTML-heavy based on code-to-text character ratio.
    
#     UPDATED: threshold=0.70 (raised from 0.40) to reduce unnecessary Gemini calls.
#     Only escalates to Gemini if 70%+ of the content is HTML/CSS/JS markup.
    
#     This dramatically improves performance for normal emails with light HTML formatting.
#     """
#     if not raw_content:
#         return False
        
#     # Get the length of the text as seen by a human
#     clean_text = clean_html_for_llm(raw_content)
#     clean_len = len(clean_text)
#     total_len = len(raw_content)
    
#     if total_len == 0:
#         return False

#     # Calculate how much of the string is 'Boilerplate' (Tags + CSS + JS)
#     code_len = total_len - clean_len
#     ratio = code_len / total_len
#     print(f"HTML Content Ratio: {ratio:.2f} (Threshold: {threshold})")
#     return ratio > threshold

def is_mostly_html(raw_content, plain_text_content, threshold=0.50):
    """
    Detects if an email is HTML-heavy by comparing the raw HTML size 
    (including text inside tags) against the standalone plain text version.
    """
    if not raw_content or not plain_text_content:
        return False
        
    html_len = len(raw_content)
    text_len = len(plain_text_content)
    
    if html_len == 0:
        return False

    # Ratio of HTML structure+content vs standalone text
    # A high ratio means the HTML version is much 'heavier' than the text version
    ratio = (html_len - text_len) / html_len
    
    print(f"📊 HTML Complexity Ratio: {ratio:.2f} (Threshold: {threshold})")
    return ratio > threshold