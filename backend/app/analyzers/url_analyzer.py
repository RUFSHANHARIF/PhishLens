import ipaddress
import re
from urllib.parse import parse_qsl, urlsplit

from app.models.url_model import ExtractedURL


COMMON_WEB_PORTS = {
    80,
    443,
}


SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "password",
    "confirm",
    "authentication",
}


REDIRECT_PARAMETERS = {
    "redirect",
    "url",
    "next",
    "continue",
    "return",
    "returnurl",
    "redirect_url",
    "redirect_uri",
    "target",
    "destination",
}


def add_indicator(url, indicator, score):
    """
    Add an indicator only once.
    """

    if indicator not in url.indicators:
        url.indicators.append(indicator)
        url.risk_score += score


def is_ip_address(hostname):
    """
    Check whether the hostname is an IPv4 or IPv6 address.
    """

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


def has_at_symbol(url):
    """
    Detect an @ symbol in the raw URL.

    The @ character can be used in URLs to make a
    misleading hostname appear before the actual destination.
    """

    if not url.raw_url:
        return False

    return "@" in url.raw_url


def has_percent_encoding(url):
    """
    Detect valid percent-encoded byte sequences.
    """

    if not url.raw_url:
        return False

    return bool(
        re.search(
            r"%[0-9a-fA-F]{2}",
            url.raw_url,
        )
    )


def has_deep_subdomain(url):
    """
    Detect hostnames with many domain labels.

    Example:

        login.security.example.com
        ^       ^        ^
        multiple subdomain levels

    IP addresses are excluded.
    """

    if not url.hostname:
        return False

    if is_ip_address(url.hostname):
        return False

    hostname = url.hostname.rstrip(".").lower()

    labels = [
        label
        for label in hostname.split(".")
        if label
    ]

    return len(labels) >= 4


def has_suspicious_keyword(url):
    """
    Detect suspicious combinations of security-related
    keywords in the URL path.

    A single word such as /login is common on legitimate
    websites, so it is not flagged by itself.
    """

    if not url.path:
        return False

    path = url.path.lower()

    words = set(
        word
        for word in re.split(
            r"[^a-z0-9]+",
            path,
        )
        if word
    )

    suspicious_combinations = {
        ("account", "verify"),
        ("account", "verification"),
        ("account", "confirm"),
        ("account", "update"),
        ("account", "password"),
        ("login", "verify"),
        ("login", "verification"),
        ("login", "confirm"),
        ("login", "update"),
        ("security", "verify"),
        ("security", "verification"),
        ("security", "update"),
        ("password", "reset"),
        ("password", "update"),
        ("authentication", "verify"),
    }

    for first, second in suspicious_combinations:

        if first in words and second in words:
            return True

    return False


def has_long_url(url):
    """
    Detect unusually long URLs.

    A threshold of 150 characters is used to identify
    URLs that may contain excessive paths or parameters.
    """

    if not url.raw_url:
        return False

    return len(url.raw_url) > 150


def has_redirect_parameter(url):
    """
    Detect query parameters commonly used to redirect
    users to another destination.
    """

    if not url.raw_url:
        return False

    try:
        parsed = urlsplit(url.raw_url)

    except ValueError:
        return False

    if not parsed.query:
        return False

    try:
        parameters = parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

    except ValueError:
        return False

    for parameter_name, _ in parameters:

        parameter_name = parameter_name.lower().strip()

        if parameter_name in REDIRECT_PARAMETERS:
            return True

    return False


def has_many_query_parameters(url):
    """
    Detect URLs containing more than four query parameters.
    """

    if not url.raw_url:
        return False

    try:
        parsed = urlsplit(url.raw_url)

    except ValueError:
        return False

    if not parsed.query:
        return False

    try:
        parameters = parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

    except ValueError:
        return False

    return len(parameters) > 4


def analyze_url(url: ExtractedURL):
    """
    Analyze a URL for security indicators.
    """

    # ---------------------------------------------------------
    # Rule 1: HTTP instead of HTTPS
    # ---------------------------------------------------------

    if url.scheme == "http":

        add_indicator(
            url,
            "uses_http",
            10,
        )

    # ---------------------------------------------------------
    # Rule 2: IP address used as hostname
    # ---------------------------------------------------------

    if is_ip_address(url.hostname):

        add_indicator(
            url,
            "ip_address_hostname",
            20,
        )

    # ---------------------------------------------------------
    # Rule 3: Unusual port
    # ---------------------------------------------------------

    if (
        url.port is not None
        and url.port not in COMMON_WEB_PORTS
    ):

        add_indicator(
            url,
            "unusual_port",
            15,
        )

    # ---------------------------------------------------------
    # Rule 4: @ symbol
    # ---------------------------------------------------------

    if has_at_symbol(url):

        add_indicator(
            url,
            "contains_at_symbol",
            20,
        )

    # ---------------------------------------------------------
    # Rule 5: Percent encoding
    # ---------------------------------------------------------

    if has_percent_encoding(url):

        add_indicator(
            url,
            "percent_encoded_url",
            10,
        )

    # ---------------------------------------------------------
    # Rule 6: Deep subdomain
    # ---------------------------------------------------------

    if has_deep_subdomain(url):

        add_indicator(
            url,
            "deep_subdomain",
            10,
        )

    # ---------------------------------------------------------
    # Rule 7: Suspicious keyword combination
    # ---------------------------------------------------------

    if has_suspicious_keyword(url):

        add_indicator(
            url,
            "suspicious_keyword",
            5,
        )

    # ---------------------------------------------------------
    # Rule 8: Long URL
    # ---------------------------------------------------------

    if has_long_url(url):

        add_indicator(
            url,
            "long_url",
            5,
        )

    # ---------------------------------------------------------
    # Rule 9: Redirect parameter
    # ---------------------------------------------------------

    if has_redirect_parameter(url):

        add_indicator(
            url,
            "redirect_parameter",
            10,
        )

    # ---------------------------------------------------------
    # Rule 10: Many query parameters
    # ---------------------------------------------------------

    if has_many_query_parameters(url):

        add_indicator(
            url,
            "many_query_parameters",
            5,
        )

    return url
