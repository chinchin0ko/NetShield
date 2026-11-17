"""A registered device; registration alone does not provision a VPN peer."""
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Device:
    id: int
    user_id: int
    name: str
    public_key: str
    created_at: datetime
