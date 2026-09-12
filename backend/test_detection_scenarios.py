from app.analyzers.detection_engine import analyze_email


def create_clean_email():
    return {
        "headers": {
            "From": "alice@example.com",
            "To": "bob@example.com",
            "Subject": "Team Meeting",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
            "Message-ID": "<12345@example.com>",
        },
        "body": {
            "plain_text": (
                "Hello Bob,\n\n"
                "Let's meet tomorrow at 10 AM.\n\n"
                "Regards,\nAlice"
            ),
            "html": None,
        },
        "attachments": [],
    }


def create_suspicious_url_email():
    return {
        "headers": {
            "From": "security@example.com",
            "To": "analyst@example.com",
            "Subject": "Urgent Security Verification",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
            "Message-ID": "<url-test@example.com>",
        },
        "body": {
            "plain_text": (
                "Your account requires immediate verification.\n\n"
                "Please visit:\n"
                "http://192.0.2.50:8080/account/verify-password"
            ),
            "html": None,
        },
        "attachments": [],
    }

def create_suspicious_attachment_email():
    return {
        "headers": {
            "From": "security@example.com",
            "To": "analyst@example.com",
            "Subject": "Important Document",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
            "Message-ID": "<attachment-test@example.com>",
        },
        "body": {
            "plain_text": (
                "Please review the attached document immediately."
            ),
            "html": None,
        },
        "attachments": [
            {
                "filename": "Invoice.pdf.exe",
                "mime_type": "application/octet-stream",
                "size": 16,
                "sha256": (
                    "d749b4dda9fbe9c0605b443fbe263eae5e5113fce55e6138a4ed92215919f1b8"
                ),
            }
        ],
    }

def create_suspicious_header_email():
    return {
        "headers": {
            "From": "security@microsoft.com",
            "Reply-To": "attacker@evil.example.net",
            "Return-Path": "attacker@evil.example.net",
            "To": "analyst@example.com",
            "Subject": "Urgent Security Alert",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
            "Message-ID": "<12345@evil.example.net>",
        },
        "body": {
            "plain_text": "Please review this security alert.",
            "html": None,
        },
        "attachments": [],
    }

def create_full_phishing_email():
    return {
        "headers": {
            "From": "security@microsoft.com",
            "Reply-To": "attacker@evil.example.net",
            "Return-Path": "attacker@evil.example.net",
            "To": "analyst@example.com",
            "Subject": "URGENT: Account Verification Required",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
            "Message-ID": "<12345@evil.example.net>",
        },
        "body": {
            "plain_text": (
                "URGENT!\n\n"
                "Your account requires immediate verification.\n\n"
                "Verify your account here:\n"
                "http://192.0.2.50:8080/account/verify-password"
            ),
            "html": None,
        },
        "attachments": [
            {
                "filename": "Invoice.pdf.exe",
                "mime_type": "application/octet-stream",
                "size": 16,
                "sha256": (
                    "d749b4dda9fbe9c0605b443fbe263eae5e5113fce55e6138a4ed92215919f1b8"
                ),
            }
        ],
    }

def print_result(name, result):
    print(f"\n=== {name} ===")
    print("Overall Score:", result["overall_score"])
    print("Overall Risk:", result["overall_risk"])
    print("URL Findings:", len(result["url_results"]))
    print("Attachment Findings:", len(result["attachment_results"]))
    print("Header Findings:", result["header_results"])

    print("Summary:")

    for item in result["summary"]:
        print("-", item)


# --------------------------------------------------
# TEST 1: CLEAN EMAIL
# --------------------------------------------------

clean_email = create_clean_email()

result = analyze_email(clean_email)

print_result(
    "CLEAN EMAIL TEST",
    result
)


# --------------------------------------------------
# TEST 2: SUSPICIOUS URL EMAIL
# --------------------------------------------------

suspicious_url_email = create_suspicious_url_email()

result = analyze_email(suspicious_url_email)

print_result(
    "SUSPICIOUS URL EMAIL TEST",
    result
)

# --------------------------------------------------
# TEST 3: SUSPICIOUS ATTACHMENT EMAIL
# --------------------------------------------------

suspicious_attachment_email = create_suspicious_attachment_email()

result = analyze_email(
    suspicious_attachment_email
)

print_result(
    "SUSPICIOUS ATTACHMENT EMAIL TEST",
    result
)

# --------------------------------------------------
# TEST 4: SUSPICIOUS HEADER EMAIL
# --------------------------------------------------

suspicious_header_email = create_suspicious_header_email()

result = analyze_email(
    suspicious_header_email
)

print_result(
    "SUSPICIOUS HEADER EMAIL TEST",
    result
)

# --------------------------------------------------
# TEST 5: FULL PHISHING EMAIL
# --------------------------------------------------

full_phishing_email = create_full_phishing_email()

result = analyze_email(
    full_phishing_email
)

print_result(
    "FULL PHISHING EMAIL TEST",
    result
)
