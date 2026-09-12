from app.parsers.email_parser import parse_eml
from app.parsers.email_normalizer import normalize_email
from app.analyzers.url_extractor import extract_urls


parsed_email = parse_eml("../samples/sample_link_mismatch.eml")

email = normalize_email(parsed_email)

urls = extract_urls(email)

print("=== HTML LINK ANALYSIS ===")

for index, url in enumerate(urls, start=1):

    print(f"\nURL #{index}")
    print("URL:", url.raw_url)
    print("Hostname:", url.hostname)
    print("Visible Text:", url.visible_text)
    print("Sources:", url.sources)
