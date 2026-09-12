from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Attachment:
    filename: Optional[str]
    mime_type: Optional[str]
    size: int
    sha256: str


@dataclass
class NormalizedEmail:
    sender: Optional[str]
    recipient: Optional[str]
    reply_to: Optional[str]
    return_path: Optional[str]
    subject: Optional[str]
    date: Optional[str]
    message_id: Optional[str]

    headers: dict = field(default_factory=dict)

    plain_text: Optional[str] = None
    html: Optional[str] = None

    attachments: list[Attachment] = field(default_factory=list)
