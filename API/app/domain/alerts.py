from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class SecurityAlert:
    event_hash: str
    occurred_at: datetime
    signature: str
    severity: int
    source_ip: str | None
    destination_ip: str | None
