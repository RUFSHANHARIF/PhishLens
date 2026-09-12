"""
PhishLens Detection Engine

Combines URL, attachment, header, authentication,
and email correlation analysis to produce an
overall email security assessment.
"""

from app.analyzers.url_analyzer import analyze_url
from app.analyzers.url_extractor import (
    extract_urls_from_text,
    extract_urls_from_html,
    deduplicate_urls,
)
from app.analyzers.attachment_analyzer import analyze_attachment
from app.analyzers.header_analyzer import analyze_headers
from app.analyzers.authentication_analyzer import (
    analyze_headers_authentication,
)
from app.analyzers.email_correlator import (
    correlate_email_findings,
)


def calculate_overall_score(
    url_results,
    attachment_results,
    header_results,
    authentication_results,
    correlation_results,
):
    """
    Calculate the combined overall email risk score.

    URL, attachment, header, authentication,
    and correlation scores are combined and
    capped at 100.
    """

    total_score = 0

    # URL scores
    for url in url_results:
        total_score += url.risk_score

    # Attachment scores
    for attachment in attachment_results:
        total_score += attachment["risk_score"]

    # Header score
    if header_results:
        total_score += header_results.get(
            "risk_score",
            0
        )

    # Authentication score
    if authentication_results:
        total_score += authentication_results.get(
            "risk_score",
            0
        )

    # Correlation score
    if correlation_results:
        total_score += correlation_results.get(
            "risk_score",
            0
        )

    # Maximum possible score
    return min(total_score, 100)


def classify_email_risk(risk_score):
    """
    Convert the overall email risk score
    into a severity level.
    """

    if risk_score >= 60:
        return "CRITICAL"

    if risk_score >= 40:
        return "HIGH"

    if risk_score >= 20:
        return "MEDIUM"

    return "LOW"


def generate_analyst_summary(
    url_results,
    attachment_results,
    header_results,
    authentication_results,
    correlation_results,
):
    """
    Generate human-readable reasons for the
    email risk assessment.
    """

    reasons = []

    # ---------------------------------------------------------
    # URL messages
    # ---------------------------------------------------------

    url_messages = {
        "uses_http":
            "URL uses HTTP instead of HTTPS",

        "ip_address_hostname":
            "URL uses an IP address instead of a domain name",

        "unusual_port":
            "URL uses an unusual network port",

        "contains_at_symbol":
            "URL contains an @ symbol that may disguise the real destination",

        "percent_encoded_url":
            "URL contains percent-encoded characters",

        "deep_subdomain":
            "URL contains multiple subdomain levels",

        "suspicious_keyword":
            "URL contains a suspicious security-related keyword",

        "long_url":
            "URL is unusually long",

        "redirect_parameter":
            "URL contains a redirect parameter",

        "many_query_parameters":
            "URL contains many query parameters",
    }

    # ---------------------------------------------------------
    # Attachment messages
    # ---------------------------------------------------------

    attachment_messages = {
        "dangerous_extension":
            "Executable or potentially dangerous attachment detected",

        "double_extension":
            "Attachment uses a suspicious double extension",

        "suspicious_filename":
            "Attachment filename contains suspicious wording",

        "dangerous_mime_type":
            "Attachment uses a potentially dangerous MIME type",
    }

    # ---------------------------------------------------------
    # Header messages
    # ---------------------------------------------------------

    header_messages = {
        "missing_from":
            "Email is missing the From header",

        "missing_to":
            "Email is missing the To header",

        "missing_subject":
            "Email is missing the Subject header",

        "missing_date":
            "Email is missing the Date header",

        "missing_message_id":
            "Email is missing the Message-ID header",

        "reply_to_mismatch":
            "From and Reply-To addresses use different domains",

        "return_path_mismatch":
            "From and Return-Path addresses use different domains",

        "message_id_domain_mismatch":
            "From and Message-ID addresses use different domains",

        "display_name_spoofing":
            "Sender display name appears to impersonate a trusted organization",

        "lookalike_domain":
            "Sender domain appears similar to a trusted organization",
    }

    # ---------------------------------------------------------
    # Authentication messages
    # ---------------------------------------------------------

    authentication_messages = {
        "spf_fail":
            "SPF authentication failed",

        "spf_softfail":
            "SPF authentication returned softfail",

        "spf_neutral":
            "SPF authentication returned neutral",

        "dkim_fail":
            "DKIM authentication failed",

        "dkim_neutral":
            "DKIM authentication returned neutral",

        "dmarc_fail":
            "DMARC authentication failed",

        "dmarc_bestguesspass":
            "DMARC returned best-guess pass",
    }

    # ---------------------------------------------------------
    # Correlation messages
    # ---------------------------------------------------------

    correlation_messages = {
        "multiple_detection_categories":
            "Multiple independent email security categories contain findings",

        "suspicious_url_and_attachment":
            "Suspicious URL and attachment detected together",

        "header_authentication_mismatch":
            "Suspicious header and authentication findings detected together",

        "multi_layer_phishing_evidence":
            "Multiple independent phishing indicators detected across email layers",
    }

    # ---------------------------------------------------------
    # URL findings
    # ---------------------------------------------------------

    for url in url_results:

        for indicator in url.indicators:

            message = url_messages.get(
                indicator,
                f"URL security indicator detected: {indicator}"
            )

            reasons.append(
                f"{message}: {url.raw_url}"
            )

    # ---------------------------------------------------------
    # Attachment findings
    # ---------------------------------------------------------

    for attachment in attachment_results:

        filename = attachment["filename"]

        for indicator in attachment["indicators"]:

            message = attachment_messages.get(
                indicator,
                f"Attachment security indicator detected: {indicator}"
            )

            reasons.append(
                f"{message}: {filename}"
            )

    # ---------------------------------------------------------
    # Header findings
    # ---------------------------------------------------------

    if header_results:

        for indicator in header_results.get(
            "indicators",
            []
        ):

            message = header_messages.get(
                indicator,
                f"Header security indicator detected: {indicator}"
            )

            reasons.append(message)

    # ---------------------------------------------------------
    # Authentication findings
    # ---------------------------------------------------------

    if authentication_results:

        for indicator in authentication_results.get(
            "indicators",
            []
        ):

            message = authentication_messages.get(
                indicator,
                f"Authentication security indicator detected: {indicator}"
            )

            reasons.append(message)

    # ---------------------------------------------------------
    # Correlation findings
    # ---------------------------------------------------------

    if correlation_results:

        for indicator in correlation_results.get(
            "indicators",
            []
        ):

            message = correlation_messages.get(
                indicator,
                f"Email correlation indicator detected: {indicator}"
            )

            reasons.append(message)

    return reasons


def analyze_email(email):
    """
    Analyze URLs, attachments, headers,
    authentication, and correlated findings
    contained in a parsed email.
    """

    # ---------------------------------------------------------
    # Initialize results
    # ---------------------------------------------------------

    results = {
        "url_results": [],
        "attachment_results": [],
        "header_results": {},
        "authentication_results": {},
        "correlation_results": {},
    }

    # ---------------------------------------------------------
    # Get email body
    # ---------------------------------------------------------

    body = email.get(
        "body",
        {}
    )

    plain_text = body.get(
        "plain_text"
    )

    html = body.get(
        "html"
    )

    # ---------------------------------------------------------
    # Extract URLs
    # ---------------------------------------------------------

    text_urls = extract_urls_from_text(
        plain_text
    )

    html_urls = extract_urls_from_html(
        html
    )

    # ---------------------------------------------------------
    # Remove duplicate URLs
    # ---------------------------------------------------------

    urls = deduplicate_urls(
        text_urls + html_urls
    )

    # ---------------------------------------------------------
    # Analyze URLs
    # ---------------------------------------------------------

    for url in urls:

        analyzed_url = analyze_url(
            url
        )

        results["url_results"].append(
            analyzed_url
        )

    # ---------------------------------------------------------
    # Analyze attachments
    # ---------------------------------------------------------

    for attachment in email.get(
        "attachments",
        []
    ):

        analyzed_attachment = analyze_attachment(
            attachment
        )

        results["attachment_results"].append(
            analyzed_attachment
        )

    # ---------------------------------------------------------
    # Analyze headers
    # ---------------------------------------------------------

    header_results = analyze_headers(
        email.get(
            "headers",
            {}
        )
    )

    results["header_results"] = header_results

    # ---------------------------------------------------------
    # Analyze authentication
    # ---------------------------------------------------------

    authentication_results = analyze_headers_authentication(
        email.get(
            "headers",
            {}
        )
    )

    results["authentication_results"] = authentication_results

    # ---------------------------------------------------------
    # Correlate all findings
    # ---------------------------------------------------------

    correlation_results = correlate_email_findings(
        results["url_results"],
        results["attachment_results"],
        results["header_results"],
        results["authentication_results"],
    )

    results["correlation_results"] = correlation_results

    # ---------------------------------------------------------
    # Calculate overall score
    # ---------------------------------------------------------

    results["overall_score"] = calculate_overall_score(
        results["url_results"],
        results["attachment_results"],
        results["header_results"],
        results["authentication_results"],
        results["correlation_results"],
    )

    # ---------------------------------------------------------
    # Classify overall risk
    # ---------------------------------------------------------

    results["overall_risk"] = classify_email_risk(
        results["overall_score"]
    )

    # ---------------------------------------------------------
    # Generate analyst summary
    # ---------------------------------------------------------

    results["summary"] = generate_analyst_summary(
        results["url_results"],
        results["attachment_results"],
        results["header_results"],
        results["authentication_results"],
        results["correlation_results"],
    )

    return results
