from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ExtractedURL:
    raw_url: str
    source: str

    scheme: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None

    visible_text: Optional[str] = None

    sources: list[str] = field(default_factory=list)

    indicators: list[str] = field(default_factory=list)
    risk_score: int = 0

    def __post_init__(self):
        if not self.sources:
            self.sources.append(self.source)
