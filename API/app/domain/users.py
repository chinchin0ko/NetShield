"""Domain entities, independent of frameworks and storage."""
from dataclasses import dataclass


@dataclass(frozen=True)
class User:
    id: int
    username: str
    password_hash: str
    is_active: bool
