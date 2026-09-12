"""
PhishLens Email Header Analyzer

Analyzes email headers for suspicious characteristics.
"""


# Organizations commonly impersonated in phishing emails.
TRUSTED_ORGANIZATIONS = {
    "microsoft": {
        "microsoft.com",
        "microsoftonline.com",
        "office.com",
        "office365.com",
    },
    "google": {
        "google.com",
        "googlemail.com",
    },
    "apple": {
        "apple.com",
        "icloud.com",
    },
    "amazon": {
        "amazon.com",
        "amazon.co.uk",
        "amazon.in",
    },
    "paypal": {
        "paypal.com",
    },
    "linkedin": {
        "linkedin.com",
    },
    "facebook": {
        "facebook.com",
        "meta.com",
    },
}


def normalize_header_value(value):
    """
    Convert a header value to a clean string.
    """

    if value is None:
        return ""

    return str(value).strip()


def get_header(headers, name):
    """
    Retrieve a header without depending on capitalization.
    """

    target = name.lower()

    for header, value in headers.items():
        if header.lower() == target:
            return normalize_header_value(value)

    return ""


def analyze_header_presence(headers):
    """
    Check for important email headers.
    """

    indicators = []
    risk_score = 0

    if not get_header(headers, "From"):
        indicators.append("missing_from")
        risk_score += 20

    if not get_header(headers, "To"):
        indicators.append("missing_to")
        risk_score += 10

    if not get_header(headers, "Subject"):
        indicators.append("missing_subject")
        risk_score += 5

    if not get_header(headers, "Date"):
        indicators.append("missing_date")
        risk_score += 5

    if not get_header(headers, "Message-ID"):
        indicators.append("missing_message_id")
        risk_score += 10

    return indicators, risk_score


def get_email_domain(address):
    """
    Extract the domain from an email address.
    """

    if not address or "@" not in address:
        return ""

    return address.rsplit("@", 1)[1].lower().strip()


def get_email_address(from_header):
    """
    Extract the actual email address from a From header.

    Supports formats such as:

        security@example.com
        Microsoft Security <security@microsoft.com>
    """

    if not from_header:
        return ""

    if "<" in from_header and ">" in from_header:
        return from_header.split("<", 1)[1].split(">", 1)[0].strip()

    return from_header.strip()


def get_display_name(from_header):
    """
    Extract the display name from a From header.

    Example:

        Microsoft Security <attacker@evil.example.net>

    returns:

        Microsoft Security
    """

    if not from_header:
        return ""

    if "<" in from_header:
        return from_header.split("<", 1)[0].strip().strip('"')

    return ""


def has_reply_to_mismatch(headers):
    """
    Detect when Reply-To uses a different domain
    from the From address.
    """

    from_address = get_email_address(
        get_header(headers, "From")
    )

    reply_to = get_header(headers, "Reply-To")

    if not from_address or not reply_to:
        return False

    from_domain = get_email_domain(from_address)
    reply_domain = get_email_domain(reply_to)

    if not from_domain or not reply_domain:
        return False

    return from_domain != reply_domain


def has_return_path_mismatch(headers):
    """
    Detect when Return-Path uses a different domain
    from the From address.
    """

    from_address = get_email_address(
        get_header(headers, "From")
    )

    return_path = get_header(headers, "Return-Path")

    if not from_address or not return_path:
        return False

    from_domain = get_email_domain(from_address)
    return_domain = get_email_domain(return_path)

    if not from_domain or not return_domain:
        return False

    return from_domain != return_domain


def has_message_id_domain_mismatch(headers):
    """
    Detect when the Message-ID domain differs from
    the From address domain.
    """

    from_address = get_email_address(
        get_header(headers, "From")
    )

    message_id = get_header(headers, "Message-ID")

    if not from_address or not message_id:
        return False

    from_domain = get_email_domain(from_address)

    if "@" not in message_id:
        return False

    message_id_domain = message_id.rsplit("@", 1)[1]
    message_id_domain = (
        message_id_domain
        .rstrip(">")
        .lower()
        .strip()
    )

    if not from_domain or not message_id_domain:
        return False

    return from_domain != message_id_domain


def has_display_name_spoofing(headers):
    """
    Detect when a From display name appears to impersonate
    a trusted organization while the actual sender domain
    does not belong to that organization.
    """

    from_header = get_header(headers, "From")

    if not from_header:
        return False

    display_name = get_display_name(from_header)
    email_address = get_email_address(from_header)

    if not display_name or not email_address:
        return False

    sender_domain = get_email_domain(email_address)

    if not sender_domain:
        return False

    display_name_lower = display_name.lower()

    for organization, trusted_domains in TRUSTED_ORGANIZATIONS.items():

        if organization in display_name_lower:

            if sender_domain not in trusted_domains:
                return True

    return False

def has_lookalike_domain(headers):
    """
    Detect domains that appear to impersonate a trusted
    organization by embedding its name in a different domain.
    """

    from_header = get_header(headers, "From")

    if not from_header:
        return False

    email_address = get_email_address(from_header)

    if not email_address:
        return False

    sender_domain = get_email_domain(email_address)

    if not sender_domain:
        return False

    # Do not flag legitimate trusted domains.
    for organization, trusted_domains in TRUSTED_ORGANIZATIONS.items():

        if sender_domain in trusted_domains:
            continue

        # Check whether the organization name appears
        # somewhere inside the sender domain.
        if organization in sender_domain:

            return True

    return False

def analyze_headers(headers):
    """
    Analyze email headers and return security findings.
    """

    if not isinstance(headers, dict):
        headers = {}

    indicators, risk_score = analyze_header_presence(headers)

    # Rule: From / Reply-To domain mismatch
    if has_reply_to_mismatch(headers):
        indicators.append("reply_to_mismatch")
        risk_score += 25

    # Rule: From / Return-Path domain mismatch
    if has_return_path_mismatch(headers):
        indicators.append("return_path_mismatch")
        risk_score += 20

    # Rule: From / Message-ID domain mismatch
    if has_message_id_domain_mismatch(headers):
        indicators.append("message_id_domain_mismatch")
        risk_score += 15

    # Rule: Display-name spoofing
    if has_display_name_spoofing(headers):
        indicators.append("display_name_spoofing")
        risk_score += 25
    
    # Rule: Lookalike sender domain
    if has_lookalike_domain(headers):
        indicators.append("lookalike_domain")
        risk_score += 30
    return {
        "indicators": indicators,
        "risk_score": risk_score,
    }
