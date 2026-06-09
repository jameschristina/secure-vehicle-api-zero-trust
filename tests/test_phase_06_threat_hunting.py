import json
from unittest.mock import Mock, patch

from phase_06_threat_hunting import (
    analyze_logs,
    fetch_logs
)


def test_analyze_logs_normal_activity():
    logs = [
        {
            "role": "user",
            "vehicle_id": "V123",
            "client": "10.0.0.1",
            "reason": "normal_activity",
            "timestamp": "2025-01-01T00:00:00Z"
        }
    ]

    result = analyze_logs(logs)

    assert result["risk_score"] == 0
    assert result["severity"] == "LOW"
    assert result["techniques"] == {}


def test_analyze_logs_detects_mitre_techniques():
    logs = [
        {
            "role": "attacker",
            "vehicle_id": "V999",
            "client": "1.1.1.1",
            "reason": "invalid_api_key",
            "timestamp": "2025-01-01T00:00:00Z"
        },
        {
            "role": "attacker",
            "vehicle_id": "V999",
            "client": "1.1.1.1",
            "reason": "unauthorized_vehicle_access",
            "timestamp": "2025-01-01T00:00:01Z"
        }
    ]

    result = analyze_logs(logs)

    assert result["risk_score"] > 0
    assert "T1078" in result["techniques"]
    assert "T1210" in result["techniques"]
    assert result["identity_risk"]["attacker"] > 0


def test_suspicious_client_tracking():
    logs = [
        {
            "role": "user",
            "vehicle_id": "V1",
            "client": "9.9.9.9",
            "reason": "normal_activity",
            "timestamp": "2025-01-01"
        }
        for _ in range(3)
    ]

    result = analyze_logs(logs)

    assert result["suspicious_clients"]["9.9.9.9"] == 3


@patch("phase_06_threat_hunting.requests.get")
def test_fetch_logs_success(mock_get):

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "logs": [{"event": "test"}]
    }

    mock_get.return_value = mock_response

    logs = fetch_logs()

    assert logs == [{"event": "test"}]


@patch("phase_06_threat_hunting.requests.get")
def test_fetch_logs_http_failure(mock_get):

    mock_response = Mock()
    mock_response.status_code = 500

    mock_get.return_value = mock_response

    logs = fetch_logs()

    assert logs == []


@patch("phase_06_threat_hunting.requests.get")
def test_fetch_logs_exception(mock_get):

    mock_get.side_effect = Exception("connection failed")

    logs = fetch_logs()

    assert logs == []
