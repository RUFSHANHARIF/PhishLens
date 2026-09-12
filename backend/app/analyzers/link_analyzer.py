import re

from app.models.url_model import ExtractedURL


BRAND_KEYWORDS = {
    "microsoft": [
        "microsoft",
        "office365",
        "office 365",
        "outlook"
    ],
    "google": [
        "google",
        "gmail"
    ],
    "apple": [
        "apple",
        "icloud"
    ],
    "paypal": [
        "paypal"
    ]
}


def add_indicator(url, indicator, score):
    """
    Add an indicator only once.
    """

    if indicator not in url.indicators:
        url.indicators.append(indicator)
        url.risk_score += score


def normalize_text(text):
    """
    Normalize text for comparison.
    """

    if not text:
        return ""

    return re.sub(
        r'\s+',
        ' ',
        text.lower()
    ).strip()


def detect_brand_mismatch(url: ExtractedURL):
    """
    Detect potential mismatch between visible link text
    and actual URL hostname.
    """

    if not url.visible_text or not url.hostname:
        return url

    visible_text = normalize_text(url.visible_text)
    hostname = url.hostname.lower()

    for brand, keywords in BRAND_KEYWORDS.items():

        brand_in_text = any(
            keyword in visible_text
            for keyword in keywords
        )

        brand_in_hostname = any(
            keyword in hostname
            for keyword in keywords
        )

        if brand_in_text and not brand_in_hostname:

            add_indicator(
                url,
                "possible_brand_link_mismatch",
                30
            )

            break

    return url
