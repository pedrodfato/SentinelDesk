from datetime import datetime, timezone
import pytest
from pydantic import ValidationError
from backend.events import SecurityEvent

def test_valid_event_is_accepted():
    event_data = {
        "event_id": "12345",
        "scenario_id": "test_scenario",
        "host": "localhost",
        "timestamp": datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc),
        "event_type": "login",
        "user": "testuser",
        "src_ip": "192.168.1.1",
        "result": "success",
        "raw": "Sample raw event data"
    }
    event = SecurityEvent(**event_data)
    assert event.host == "localhost"

def test_naive_timestamp_is_rejected():
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_id="12345",
            scenario_id="test_scenario",
            host="localhost",
            timestamp=datetime(2026, 11, 5, 12, 0, 0),
            event_type="login",
            user="testuser",
            src_ip="192.168.1.1",
            result="success",
            raw="Sample raw event data"
        )
