from pathlib import Path


DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".msi",
    ".ps1",
    ".vbs",
    ".js",
}


DANGEROUS_MIME_TYPES = {
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-executable",
    "application/x-sh",
}


def get_file_extension(filename):
    """
    Return the file extension in lowercase.
    """

    if not filename:
        return ""

    return Path(filename).suffix.lower()


def is_dangerous_extension(filename):
    """
    Check whether an attachment has a potentially dangerous
    executable or script extension.
    """

    extension = get_file_extension(filename)

    return extension in DANGEROUS_EXTENSIONS


def has_double_extension(filename):
    """
    Detect filenames that contain a document-like extension
    followed by a potentially dangerous extension.
    """

    if not filename:
        return False

    parts = Path(filename).name.lower().split(".")

    if len(parts) < 3:
        return False

    dangerous_extensions = {
        "exe",
        "scr",
        "bat",
        "cmd",
        "com",
        "msi",
        "ps1",
        "vbs",
        "js",
    }

    document_extensions = {
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "txt",
        "jpg",
        "jpeg",
        "png",
    }

    previous_extension = parts[-2]
    final_extension = parts[-1]

    return (
        previous_extension in document_extensions
        and final_extension in dangerous_extensions
    )


def has_suspicious_filename(filename):
    """
    Detect filenames containing words commonly used
    in phishing or social-engineering attempts.
    """

    if not filename:
        return False

    filename_lower = filename.lower()

    suspicious_keywords = {
        "urgent",
        "security",
        "verify",
        "verification",
        "password",
        "reset",
        "account",
        "invoice",
        "payment",
        "update",
        "alert",
        "document",
    }

    return any(
        keyword in filename_lower
        for keyword in suspicious_keywords
    )


def has_dangerous_mime_type(attachment):
    """
    Detect MIME types commonly associated with
    executable files.
    """

    mime_type = attachment.get("mime_type")

    if not mime_type:
        return False

    return mime_type.lower() in DANGEROUS_MIME_TYPES

def classify_attachment_risk(risk_score):
    """
    Convert an attachment risk score into a severity level.
    """

    if risk_score >= 60:
        return "CRITICAL"

    if risk_score >= 40:
        return "HIGH"

    if risk_score >= 20:
        return "MEDIUM"

    return "LOW"

def analyze_attachment(attachment):
    """
    Analyze an attachment and return security findings.
    """

    indicators = []
    risk_score = 0

    filename = attachment.get("filename", "")

    # Rule 1: Dangerous extension
    if is_dangerous_extension(filename):
        indicators.append("dangerous_extension")
        risk_score += 30

    # Rule 2: Double extension
    if has_double_extension(filename):
        indicators.append("double_extension")
        risk_score += 20

    # Rule 3: Suspicious filename
    if has_suspicious_filename(filename):
        indicators.append("suspicious_filename")
        risk_score += 5

    # Rule 4: Dangerous MIME type
    if has_dangerous_mime_type(attachment):
        indicators.append("dangerous_mime_type")
        risk_score += 15

    risk_level = classify_attachment_risk(risk_score)

    return {
    "filename": filename,
    "mime_type": attachment.get("mime_type"),
    "size": attachment.get("size"),
    "sha256": attachment.get("sha256"),
    "indicators": indicators,
    "risk_score": risk_score,
    "risk_level": risk_level,
}
