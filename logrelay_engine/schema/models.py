from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class User:
    user_id: int
    username: str
    access_level: str

    def validate(self) -> None:
        if not isinstance(self.user_id, int) or self.user_id <= 0:
            raise ValueError("user_id must be a positive integer")
        if not self.username or not isinstance(self.username, str):
            raise ValueError("username cannot be empty")
        if self.access_level not in {"ADMIN", "USER", "ANONYMOUS", "BOT"}:
            raise ValueError("invalid access_level")


@dataclass(frozen=True)
class IPRegistry:
    ip_address: str
    subnet: str
    geo_location: str

    def validate(self) -> None:
        if not self.ip_address or not isinstance(self.ip_address, str):
            raise ValueError("ip_address cannot be empty")
        if not self.subnet or not isinstance(self.subnet, str):
            raise ValueError("subnet cannot be empty")


@dataclass(frozen=True)
class EventType:
    type_code: str
    http_status: int
    description: str

    def validate(self) -> None:
        if not self.type_code or not isinstance(self.type_code, str):
            raise ValueError("type_code cannot be empty")
        if not (100 <= self.http_status <= 599):
            raise ValueError("http_status must be a valid 3-digit HTTP code")


@dataclass(frozen=True)
class SecurityEvent:
    event_id: int
    timestamp: datetime
    user_id: int
    ip_address: str
    type_code: str
    path: str
    user_agent: str

    def validate(self) -> None:
        if not isinstance(self.event_id, int) or self.event_id <= 0:
            raise ValueError("event_id must be a positive integer")
        if not isinstance(self.timestamp, datetime):
            raise ValueError("timestamp must be a valid datetime instance")
        if not isinstance(self.user_id, int) or self.user_id <= 0:
            raise ValueError("user_id must be a valid foreign key integer")
        if not self.ip_address:
            raise ValueError("ip_address foreign key cannot be empty")
        if not self.type_code:
            raise ValueError("type_code foreign key cannot be empty")