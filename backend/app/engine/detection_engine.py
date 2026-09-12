from app.analyzers.url_analyzer import analyze_url
from app.analyzers.link_analyzer import detect_brand_mismatch


def analyze_url_completely(url):
    """
    Run all available URL detection rules.
    """

    # Run basic URL analysis
    analyze_url(url)

    # Run HTML link analysis
    detect_brand_mismatch(url)

    return url
