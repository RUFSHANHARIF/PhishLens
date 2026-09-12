"""
PhishLens Email Correlator

Correlates findings from URL, attachment, header,
and authentication analysis to identify combinations
of suspicious behavior.
"""


def correlate_email_findings(
    url_results,
    attachment_results,
    header_results,
    authentication_results,
):
    """
    Correlate findings from all PhishLens analysis layers.

    Returns:
        {
            "indicators": [],
            "risk_score": 0,
            "categories": []
        }
    """

    indicators = []
    categories = []

    # ---------------------------------------------------------
    # Determine which analysis categories contain findings
    # ---------------------------------------------------------

    if url_results:
        categories.append("url")

    if attachment_results:
        categories.append("attachment")

    if header_results and header_results.get("indicators"):
        categories.append("header")

    if authentication_results and authentication_results.get("indicators"):
        categories.append("authentication")

    # ---------------------------------------------------------
    # Rule 1: Multiple detection categories
    # ---------------------------------------------------------

    if len(categories) >= 2:
        indicators.append(
            "multiple_detection_categories"
        )

    # ---------------------------------------------------------
    # Rule 2: Suspicious URL + attachment
    # ---------------------------------------------------------

    if url_results and attachment_results:
        indicators.append(
            "suspicious_url_and_attachment"
        )

    # ---------------------------------------------------------
    # Rule 3: Header + authentication findings
    # ---------------------------------------------------------

    if (
        header_results
        and header_results.get("indicators")
        and authentication_results
        and authentication_results.get("indicators")
    ):
        indicators.append(
            "header_authentication_mismatch"
        )

    # ---------------------------------------------------------
    # Rule 4: Strong multi-layer phishing evidence
    # ---------------------------------------------------------

    if len(categories) >= 3:
        indicators.append(
            "multi_layer_phishing_evidence"
        )

    # ---------------------------------------------------------
    # Correlation risk score
    # ---------------------------------------------------------

    risk_score = 0

    if "multiple_detection_categories" in indicators:
        risk_score += 10

    if "suspicious_url_and_attachment" in indicators:
        risk_score += 15

    if "header_authentication_mismatch" in indicators:
        risk_score += 15

    if "multi_layer_phishing_evidence" in indicators:
        risk_score += 20

    return {
        "indicators": indicators,
        "risk_score": risk_score,
        "categories": categories,
    }
