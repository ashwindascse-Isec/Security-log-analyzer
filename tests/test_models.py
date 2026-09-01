from datetime import datetime
import pytest
from logrelay_engine.schema.models import EventType, IPRegistry, SecurityEvent, User


def test_valid_user():
    user = User(user_id=1, username="admin", access_level="ADMIN")
    user.validate()
    assert user.user_id == 1


def test_invalid_user():
    user = User(user_id=-1, username="", access_level="INVALID")
    with pytest.raises(ValueError):
        user.validate()


def test_valid_ip_registry():
    ip_entry = IPRegistry(
        ip_address="192.168.1.50", subnet="192.168.1.0/24", geo_location="LOCAL"
    )
    ip_entry.validate()
    assert ip_entry.ip_address == "192.168.1.50"


def test_invalid_ip_registry():
    ip_entry = IPRegistry(ip_address="", subnet="", geo_location="UNKNOWN")
    with pytest.raises(ValueError):
        ip_entry.validate()


def test_valid_event_type():
    event_type = EventType(
        type_code="HTTP_401",
        http_status=401,
        description="Unauthorized login attempt",
    )
    event_type.validate()
    assert event_type.http_status == 401


def test_invalid_event_type():
    event_type = EventType(
        type_code="BAD_STATUS",
        http_status=999,
        description="Out of bounds HTTP code",
    )
    with pytest.raises(ValueError):
        event_type.validate()


def test_valid_security_event():
    event = SecurityEvent(
        event_id=101,
        timestamp=datetime.now(),
        user_id=1,
        ip_address="192.168.1.100",
        type_code="HTTP_401",
        path="/admin",
        user_agent="python-requests/2.28",
    )
    event.validate()
    assert event.event_id == 101


def test_invalid_security_event():
    event = SecurityEvent(
        event_id=-1,
        timestamp="invalid-time",  # type: ignore
        user_id=0,
        ip_address="",
        type_code="",
        path="/login",
        user_agent="curl/7.68.0",
    )
    with pytest.raises(ValueError):
        event.validate()