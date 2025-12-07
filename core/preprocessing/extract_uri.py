import re


HTML_TAG_RE = re.compile(r"<[^>]+>")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1F\x7F]")




def _clean_html_and_control(text: str) -> str:
text = HTML_TAG_RE.sub(' ', text)
text = CONTROL_CHAR_RE.sub(' ', text)
text = re.sub(r"\s+", ' ', text).strip()
return text




def extract_urls_and_mask(text: str) -> Tuple[str, List[str]]:
"""Find URLs and replace them with the <URL> placeholder.


Returns (masked_text, list_of_urls_in_order).
"""
text = _clean_html_and_control(text)


urls: List[str] = []


def _mask_match(m: re.Match) -> str:
u = m.group('url')
urls.append(u)
return ' <URL> '


masked = URL_REGEX.sub(_mask_match, text)
masked = re.sub(r"\s+", ' ', masked).strip()
return masked, urls




def parse_domain(url: str) -> str:
try:
if not url.lower().startswith(('http://', 'https://')):
url = 'http://' + url
p = urlparse(url)
return p.hostname or ''
except Exception:
return ''