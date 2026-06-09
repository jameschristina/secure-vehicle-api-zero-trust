import json
from phase_08.phase_08_threat_intelligence_correlations import (
    correlate_iocs,
    fetch_logs,
    KNOWN_BAD_IDENTITIES,
)


# -----------------------------
# TEST 1: IOC correlation hit
# -----------------------------
def test_correlate_iocs_detects_known_identity():
    logs = [
        {
            "role": "developer",
            "vehicle_id": "V123",
            "reason": "invalid_api_key",
            "timestamp": "2025-01-01T00:00:00Z",
        }
    ]

    findings = correlate_iocs(logs)

    assert len(findings) == 1
    assert findings[0]["identity"] == "developer"
    assert findings[0]["severity"] == "HIGH"


# -----------------------------
# TEST 2: No match case
# -----------------------------
def test_correlate_iocs_no_match():
    logs = [
        {
            "role": "analyst",
            "vehicle_id": "V999",
            "reason": "normal_activity",
            "timestamp": "2025-01-01T00:00:00Z",
        }
    ]

    findings = correlate_iocs(logs)
    assert findings == []


# -----------------------------
# TEST 3: constants exist
# -----------------------------
def test_known_bad_identities_loaded():
    assert "developer" in KNOWN_BAD_IDENTITIES
    assert "unknown" in KNOWN_BAD_IDENTITIES


# -----------------------------
# TEST 4: fetch_logs fallback (invalid URL simulation)
# -----------------------------
def test_fetch_logs_failure(monkeypatch):
    import phase_08.phase_08_threat_intelligence_correlations as mod

    class FakeResponse:
        status_code = 500

        def json(self):
            return {}

    def fake_get(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(mod.requests, "get", fake_get)

    logs = mod.fetch_logs()
    assert logs == []


# -----------------------------
# TEST 5: fetch_logs exception path
# -----------------------------
def test_fetch_logs_exception(monkeypatch):
    import phase_08.phase_08_threat_intelligence_correlations as mod

    def fake_get(*args, **kwargs):
        raise Exception("network failure")

    monkeypatch.setattr(mod.requests, "get", fake_get)

    logs = mod.fetch_logs()
    assert logs == []


# -----------------------------
# TEST 6: FULL correlation mix
# -----------------------------
def test_correlate_iocs_mixed_logs():
    logs = [
        {
            "role": "developer",
            "vehicle_id": "V1",
            "reason": "invalid_api_key",
            "timestamp": "t1",
        },
        {
            "role": "unknown",
            "vehicle_id": "V2",
            "reason": "missing_api_key",
            "timestamp": "t2",
        },
        {
            "role": "analyst",
            "vehicle_id": "V3",
            "reason": "normal_activity",
            "timestamp": "t3",
        },
    ]

    findings = correlate_iocs(logs)

    # should only match 2 known bad identities
    assert len(findings) == 2
    severities = {f["severity"] for f in findings}
    assert "HIGH" in severities
    assert "CRITICAL" in severities
