from app.parsers.email_parser import parse_eml
from app.parsers.email_normalizer import normalize_email
from app.analyzers.url_extractor import extract_urls
from app.analyzers.link_analyzer import detect_brand_mismatch


parsed_email = parse_eml("../samples/sample_link_mismatch.eml")

email = normalize_email(parsed_email)

urls = extract_urls(email)

print("=== LINK MISMATCH ANALYSIS ===")

for index, url in enumerate(urls, start=1):

    detect_brand_mismatch(url)

    print(f"\nURL #{index}")
    print("URL:", url.raw_url)
    print("Visible Text:", url.visible_text)
    print("Hostname:", url.hostname)
    print("Indicators:", url.indicators)
    print("Risk Score:", url.risk_score)
