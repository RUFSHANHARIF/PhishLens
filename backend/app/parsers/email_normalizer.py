from app.models.email_model import NormalizedEmail, Attachment


def normalize_email(parsed_email):
    """
    Convert the parser output into the standard PhishLens format.
    """

    attachments = []

    for item in parsed_email.get("attachments", []):
        attachment = Attachment(
            filename=item.get("filename"),
            mime_type=item.get("mime_type"),
            size=item.get("size", 0),
            sha256=item.get("sha256", "")
        )

        attachments.append(attachment)

    normalized = NormalizedEmail(
        sender=parsed_email.get("from"),
        recipient=parsed_email.get("to"),
        reply_to=parsed_email.get("reply_to"),
        return_path=parsed_email.get("return_path"),
        subject=parsed_email.get("subject"),
        date=parsed_email.get("date"),
        message_id=parsed_email.get("message_id"),
        headers=parsed_email.get("headers", {}),
        plain_text=parsed_email.get("body", {}).get("plain_text"),
        html=parsed_email.get("body", {}).get("html"),
        attachments=attachments
    )

    return normalized
