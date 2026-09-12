import hashlib

from email import policy
from email.parser import BytesParser


# ============================================================
# SHA-256
# ============================================================

def calculate_sha256(data):
    """
    Calculate the SHA-256 hash of binary data.
    """

    return hashlib.sha256(data).hexdigest()


# ============================================================
# HEADER EXTRACTION
# ============================================================

def extract_headers(message):
    """
    Extract all email headers while preserving duplicate headers.
    """

    headers = {}

    for name, value in message.raw_items():

        if name in headers:

            if isinstance(headers[name], list):

                headers[name].append(value)

            else:

                headers[name] = [
                    headers[name],
                    value
                ]

        else:

            headers[name] = value

    return headers


# ============================================================
# EMAIL PARSER
# ============================================================

def parse_eml(file_path):
    """
    Parse an .eml file and extract email information.

    The parser preserves the existing PhishLens data structure
    while handling multipart messages and unusual MIME parts
    more safely.
    """

    # --------------------------------------------------------
    # Parse email
    # --------------------------------------------------------

    with open(
        file_path,
        "rb"
    ) as email_file:

        message = BytesParser(
            policy=policy.default
        ).parse(
            email_file
        )


    # --------------------------------------------------------
    # Basic email information
    # --------------------------------------------------------

    email_data = {

        "from": message.get("From"),

        "to": message.get("To"),

        "reply_to": message.get("Reply-To"),

        "return_path": message.get("Return-Path"),

        "subject": message.get("Subject"),

        "date": message.get("Date"),

        "message_id": message.get("Message-ID"),

        "headers": extract_headers(
            message
        ),

        "body": {
            "plain_text": None,
            "html": None
        },

        "attachments": []
    }


    # --------------------------------------------------------
    # Body parts
    # --------------------------------------------------------

    plain_parts = []
    html_parts = []


    # --------------------------------------------------------
    # Walk MIME structure
    # --------------------------------------------------------

    for part in message.walk():

        # ----------------------------------------------------
        # Skip multipart container parts
        # ----------------------------------------------------

        if part.is_multipart():

            continue


        content_type = (
            part.get_content_type()
        )

        disposition = (
            part.get_content_disposition()
        )


        # ----------------------------------------------------
        # Attachment
        # ----------------------------------------------------

        if disposition == "attachment":

            filename = part.get_filename()

            attachment_data = (
                part.get_payload(
                    decode=True
                )
            )

            # -----------------------------------------------
            # Ignore attachments with no decodable payload
            # -----------------------------------------------

            if attachment_data is None:

                continue


            attachment = {

                "filename": filename,

                "mime_type": content_type,

                "size": len(
                    attachment_data
                ),

                "sha256": calculate_sha256(
                    attachment_data
                )
            }


            email_data[
                "attachments"
            ].append(
                attachment
            )

            continue


        # ----------------------------------------------------
        # Inline / normal text content
        # ----------------------------------------------------

        if (
            disposition != "attachment"
            and content_type == "text/plain"
        ):

            try:

                content = part.get_content()

            except Exception:

                content = None


            if content:

                plain_parts.append(
                    str(content)
                )


        elif (
            disposition != "attachment"
            and content_type == "text/html"
        ):

            try:

                content = part.get_content()

            except Exception:

                content = None


            if content:

                html_parts.append(
                    str(content)
                )


    # --------------------------------------------------------
    # Combine multiple body parts
    # --------------------------------------------------------

    if plain_parts:

        email_data[
            "body"
        ][
            "plain_text"
        ] = "\n\n".join(
            plain_parts
        )


    if html_parts:

        email_data[
            "body"
        ][
            "html"
        ] = "\n\n".join(
            html_parts
        )


    return email_data
