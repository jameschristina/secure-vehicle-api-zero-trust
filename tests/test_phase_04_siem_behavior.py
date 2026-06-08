import pytest
from phase_04_siem_detection import process_event


def test_normal_event_no_alert():
    event = {
        "user": "alice",
        "action": "view_vehicle",
        "vehicle_id": "V123",
        "auth": True
    }

    result = process_event(event)

    assert result["alert_generated"] is False
    assert result["severity"] == 0


def test_suspicious_event_generates_alert():
    event = {
        "user": "alice",
        "action": "unlock_vehicle",
        "vehicle_id": "V999",  # unauthorized
        "auth": True
    }

    result = process_event(event)

    assert result["alert_generated"] is True
    assert result["severity"] > 0


def test_alert_contains_required_fields():
    event = {
        "user": "bob",
        "action": "unlock_vehicle",
        "vehicle_id": "V999",
        "auth": True
    }

    result = process_event(event)

    if result["alert_generated"]:
        assert "severity" in result
        assert "event_type" in result
