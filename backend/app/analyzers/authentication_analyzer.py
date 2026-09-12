"""
PhishLens Email Authentication Analyzer

Analyzes email authentication information including:
- Authentication-Results
- Received-SPF
- SPF
- DKIM
- DMARC

Risk is assigned only to suspicious authentication states.
Successful authentication is recorded as evidence but does
not increase the risk score.
"""


def normalize_authentication_value(value):
    """
    Convert an authentication header value into a clean,
    lowercase string.
    """

    if value is None:
        return ""

    return str(value).strip().lower()


def get_header(headers, name):
    """
    Retrieve a header without depending on capitalization.
    """

    if not isinstance(headers, dict):
        return ""

    target = name.lower()

    for header, value in headers.items():
        if str(header).lower() == target:
            return str(value).strip()

    return ""


def add_indicator(indicators, indicator):
    """
    Add an indicator only once.
    """

    if indicator not in indicators:
        indicators.append(indicator)


def analyze_authentication_results(headers):
    """
    Analyze the Authentication-Results header.

    Detects SPF, DKIM, and DMARC states.
    """

    indicators = []
    risk_score = 0

    authentication_results = get_header(
        headers,
        "Authentication-Results"
    )

    if not authentication_results:
        return indicators, risk_score

    value = normalize_authentication_value(
        authentication_results
    )

    # ---------------------------------------------------------
    # SPF
    # ---------------------------------------------------------

    if "spf=fail" in value:
        add_indicator(indicators, "spf_fail")
        risk_score += 25

    elif "spf=softfail" in value:
        add_indicator(indicators, "spf_softfail")
        risk_score += 15

    elif "spf=neutral" in value:
        add_indicator(indicators, "spf_neutral")
        risk_score += 5

    elif "spf=temperror" in value:
        add_indicator(indicators, "spf_temperror")
        risk_score += 10

    elif "spf=permerror" in value:
        add_indicator(indicators, "spf_permerror")
        risk_score += 15

    elif "spf=pass" in value:
        add_indicator(indicators, "spf_pass")

    # ---------------------------------------------------------
    # DKIM
    # ---------------------------------------------------------

    if "dkim=fail" in value:
        add_indicator(indicators, "dkim_fail")
        risk_score += 25

    elif "dkim=neutral" in value:
        add_indicator(indicators, "dkim_neutral")
        risk_score += 5

    elif "dkim=temperror" in value:
        add_indicator(indicators, "dkim_temperror")
        risk_score += 10

    elif "dkim=permerror" in value:
        add_indicator(indicators, "dkim_permerror")
        risk_score += 15

    elif "dkim=pass" in value:
        add_indicator(indicators, "dkim_pass")

    # ---------------------------------------------------------
    # DMARC
    # ---------------------------------------------------------

    if "dmarc=fail" in value:
        add_indicator(indicators, "dmarc_fail")
        risk_score += 30

    elif "dmarc=bestguesspass" in value:
        add_indicator(indicators, "dmarc_bestguesspass")
        risk_score += 5

    elif "dmarc=temperror" in value:
        add_indicator(indicators, "dmarc_temperror")
        risk_score += 10

    elif "dmarc=permerror" in value:
        add_indicator(indicators, "dmarc_permerror")
        risk_score += 15

    elif "dmarc=pass" in value:
        add_indicator(indicators, "dmarc_pass")

    return indicators, risk_score


def analyze_received_spf(headers):
    """
    Analyze Received-SPF.

    Received-SPF is only scored when Authentication-Results
    does not already provide an SPF result. This prevents
    the same SPF failure from being counted twice.
    """

    indicators = []
    risk_score = 0

    received_spf = get_header(
        headers,
        "Received-SPF"
    )

    if not received_spf:
        return indicators, risk_score

    # ---------------------------------------------------------
    # Check whether Authentication-Results already contains SPF
    # ---------------------------------------------------------

    authentication_results = get_header(
        headers,
        "Authentication-Results"
    )

    auth_value = normalize_authentication_value(
        authentication_results
    )

    if "spf=" in auth_value:
        return indicators, risk_score

    # ---------------------------------------------------------
    # Analyze Received-SPF
    # ---------------------------------------------------------

    value = normalize_authentication_value(
        received_spf
    )

    if value.startswith("fail"):
        add_indicator(indicators, "received_spf_fail")
        risk_score += 25

    elif value.startswith("softfail"):
        add_indicator(indicators, "received_spf_softfail")
        risk_score += 15

    elif value.startswith("neutral"):
        add_indicator(indicators, "received_spf_neutral")
        risk_score += 5

    elif value.startswith("temperror"):
        add_indicator(indicators, "received_spf_temperror")
        risk_score += 10

    elif value.startswith("permerror"):
        add_indicator(indicators, "received_spf_permerror")
        risk_score += 15

    elif value.startswith("pass"):
        add_indicator(indicators, "received_spf_pass")

    return indicators, risk_score


def analyze_headers_authentication(headers):
    """
    Analyze all available email authentication information.
    """

    if not isinstance(headers, dict):
        headers = {}

    indicators = []
    risk_score = 0

    # ---------------------------------------------------------
    # Authentication-Results
    # ---------------------------------------------------------

    auth_indicators, auth_score = analyze_authentication_results(
        headers
    )

    for indicator in auth_indicators:
        add_indicator(indicators, indicator)

    risk_score += auth_score

    # ---------------------------------------------------------
    # Received-SPF
    # ---------------------------------------------------------

    spf_indicators, spf_score = analyze_received_spf(
        headers
    )

    for indicator in spf_indicators:
        add_indicator(indicators, indicator)

    risk_score += spf_score

    # ---------------------------------------------------------
    # Return results
    # ---------------------------------------------------------

    return {
        "indicators": indicators,
        "risk_score": risk_score,
    }
