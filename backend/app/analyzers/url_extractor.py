import re
from urllib.parse import urlparse

from app.models.url_model import ExtractedURL


URL_PATTERN = re.compile(
    r'https?://[^\s<>"\']+',
    re.IGNORECASE
)


def parse_url(url, source):
    """
    Convert a raw URL into a structured ExtractedURL object.
    """

    parsed = urlparse(url)

    return ExtractedURL(
        raw_url=url,
        source=source,
        scheme=parsed.scheme,
        hostname=parsed.hostname,
        port=parsed.port,
        path=parsed.path
    )


def extract_urls_from_text(text):
    """
    Extract HTTP and HTTPS URLs from plain text.
    """

    if not text:
        return []

    return [
        parse_url(url, "plain_text")
        for url in URL_PATTERN.findall(text)
    ]


def extract_urls_from_html(html):
    """
    Extract URLs and visible link text from HTML.
    """

    if not html:
        return []

    link_pattern = re.compile(
        r'<a\s+[^>]*href\s*=\s*["\'](https?://[^"\']+)["\'][^>]*>'
        r'(.*?)'
        r'</a>',
        re.IGNORECASE | re.DOTALL
    )

    results = []

    for match in link_pattern.finditer(html):

        url = match.group(1)

        visible_text = re.sub(
            r'<[^>]+>',
            '',
            match.group(2)
        ).strip()

        parsed_url = parse_url(url, "html")

        parsed_url.visible_text = visible_text

        results.append(parsed_url)

    return results


def deduplicate_urls(urls):
    """
    Remove duplicate URLs while preserving their sources.
    """

    unique_urls = {}

    for url in urls:

        key = url.raw_url.rstrip("/")

        if key not in unique_urls:
            unique_urls[key] = url

        else:
            existing = unique_urls[key]

            if url.source not in existing.sources:
                existing.sources.append(url.source)

            if url.visible_text and not existing.visible_text:
                existing.visible_text = url.visible_text

    return list(unique_urls.values())


def extract_urls(email):
    """
    Extract URLs from both plain-text and HTML email content
    and remove duplicates.
    """

    results = []

    results.extend(
        extract_urls_from_text(email.plain_text)
    )

    results.extend(
        extract_urls_from_html(email.html)
    )

    return deduplicate_urls(results)
