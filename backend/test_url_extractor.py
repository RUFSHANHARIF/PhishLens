from app.parsers.email_parser import parse_eml
from app.parsers.email_normalizer import normalize_email
from app.analyzers.url_extractor import extract_urls


parsed_email = parse_eml("../samples/sample_urls.eml")

email = normalize_email(parsed_email)

urls = extract_urls(email)

print("=== UNIQUE EXTRACTED URLs ===")

for index, item in enumerate(urls, start=1):
    print(f"\nURL #{index}")
    print("Raw URL:", item.raw_url)
    print("Sources:", item.sources)
    print("Scheme:", item.scheme)
    print("Hostname:", item.hostname)
    print("Port:", item.port)
    print("Path:", item.path)
