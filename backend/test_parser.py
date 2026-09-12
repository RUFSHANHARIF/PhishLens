from app.parsers.email_parser import parse_eml


email = parse_eml("../samples/sample_attachments.eml")

print("From:", email["from"])
print("To:", email["to"])
print("Reply-To:", email["reply_to"])
print("Return-Path:", email["return_path"])
print("Subject:", email["subject"])
print("Date:", email["date"])
print("Message-ID:", email["message_id"])

print("\n--- Plain Text Body ---")
print(email["body"]["plain_text"])

print("\n--- HTML Body ---")
print(email["body"]["html"])

print("\n--- Attachments ---")
print(email["attachments"])

print("\n--- All Headers ---")

for header, value in email["headers"].items():
    print(f"{header}: {value}")
