from app.parsers.email_parser import parse_eml
from app.parsers.email_normalizer import normalize_email


parsed_email = parse_eml("../samples/sample_received.eml")

email = normalize_email(parsed_email)

print("=== NORMALIZED EMAIL ===")

print("Sender:", email.sender)
print("Recipient:", email.recipient)
print("Reply-To:", email.reply_to)
print("Return-Path:", email.return_path)
print("Subject:", email.subject)
print("Date:", email.date)
print("Message-ID:", email.message_id)

print("\nReceived headers:")

received = email.headers.get("Received")

if isinstance(received, list):
    for index, value in enumerate(received, start=1):
        print(f"{index}. {value}")
else:
    print(received)

print("\nAttachments:")

for attachment in email.attachments:
    print("Filename:", attachment.filename)
    print("MIME type:", attachment.mime_type)
    print("Size:", attachment.size)
    print("SHA-256:", attachment.sha256)
