# import re
# from urllib.parse import urlparse
# import tldextract  # Third-party library for better domain parsing

from urlextract import URLExtract

# Alternative: Using a dedicated URL extraction library
def extract_uri(text):
    """
    Most reliable solution using the urlextract library.
    Install with: pip install urlextract
    """
        
    extractor = URLExtract()
    urls = extractor.find_urls(text)
    
    # Replace URLs
    new_text = text
    for url in urls:
        new_text = new_text.replace(url, '[URL]')
    
    return urls, new_text

# def extract_and_replace_urls(text):
#     """
#     Extract all URLs from text and replace them with [URL].
#     Uses a more comprehensive approach with fallback mechanisms.
    
#     Args:
#         text (str): Input text containing URLs
    
#     Returns:
#         tuple: (list_of_urls, new_text)
#     """
#     # Enhanced URL pattern with better coverage
#     url_pattern = r'(?:(?:https?|ftp)://|www\.)[^\s/$.?#].[^\s]*'
    
#     # Find all potential URLs
#     url_matches = re.findall(url_pattern, text)
    
#     # Validate and filter URLs using urlparse
#     valid_urls = []
#     for url in url_matches:
#         try:
#             # Add protocol if missing
#             if url.startswith('www.'):
#                 url = 'http://' + url
            
#             # Parse and validate
#             parsed = urlparse(url)
#             if parsed.scheme and parsed.netloc:
#                 # Additional validation for TLD
#                 extracted = tldextract.extract(url)
#                 if extracted.suffix:  # Has a valid TLD
#                     valid_urls.append(url)
#         except:
#             continue  # Skip invalid URLs
    
#     # Create replacement text
#     new_text = text
#     for url in valid_urls:
#         # Handle URLs that might appear as www. in original
#         display_url = url.replace('http://', '').replace('https://', '')
#         if display_url.startswith('www.'):
#             new_text = new_text.replace(display_url, '[URL]')
#         new_text = new_text.replace(url, '[URL]')
    
#     return valid_urls, new_text



