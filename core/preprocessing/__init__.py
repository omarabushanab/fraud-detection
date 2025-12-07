def preprocess_text(text: str, *, arabizi_to_ar: bool = False) ->  Tuple[str,List[str]]:
    """Preprocess a single text message for XLM-R.


    Returns:
    (normalized_text, extracted_urls)


    Steps:
    - Extract & mask URLs (returns list of extracted urls and text with <URL> placeholders)
    - Clean control / HTML noise is handled inside extract_urls_and_mask
    - Light normalization for Arabic and English
    - Optional conservative Arabizi -> Arabic conversion (disabled by default)


    Keep code-mixing intact.
    """
    text_with_mask, urls = extract_urls_and_mask(text)


    # If Arabizi likely present and user wants transliteration, convert first.
    if arabizi_to_ar and detect_arabizi(text_with_mask):
        text_with_mask = convert_arabizi(text_with_mask)


    # Normalize Arabic (will no-op on pure English text)
    text_with_mask = normalize_arabic(text_with_mask)


    # Normalize English / Latin segments
    text_with_mask = normalize_english(text_with_mask)


    return text_with_mask, urls