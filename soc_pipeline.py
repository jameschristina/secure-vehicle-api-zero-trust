"""
SOC PIPELINE ORCHESTRATOR (UNIFIED ENTERPRISE SCHEMA)
SIEM → Detection → Hunting → Intel → Incident → SOAR
"""

from datetime import datetime, timezone

import requests

from soc_scoring import compute_severity

from phase_04_siem_detection import analyze_event as siem_process
from phase_05_detection_engineering import analyze_event as detect_engine
from phase_06_threat_hunting import analyze_logs as threat_hunt
from phase_07_incident_response import incident_response
from phase_08_threat_intelligence_correlations import correlate_iocs
from phase_09_soar_automation import process_alert


# =========================================================
# STATE
# =========================================================
pipeline_state = {
    "events_processed": 0,
    "alerts": [],
    "incidents": [],
    "responses": []
}


# =========================================================
# SAFE WRAPPER
# =========================================================
def safe_call(fn, fallback, *args):
    try:
        result = fn(*args)
        return result if isinstance(result, dict) else fallback
    except Exception:
        return fallback


# =========================================================
# CORE PIPELINE (FULL SOC FLOW)
# =========================================================
def process_pipeline(event: dict):

    # 1. SIEM
    siem_result = safe_call(siem_process, {"risk_score": 0}, event)

    # 2. Detection Engineering
    detect_result = safe_call(detect_engine, {"risk_score": 0}, event)

    # 3. Threat Hunting (expects list)
    hunt_result = safe_call(
        threat_hunt,
        {"risk_score": 0, "techniques": {}, "suspicious_clients": {}},
        [event]
    )

    # 4. Threat Intel
    intel_result = safe_call(correlate_iocs, {}, [event])

    # =====================================================
    # UNIFIED SCORING (ONLY SOURCE OF TRUTH)
    # =====================================================
    risk_score = (
        siem_result.get("risk_score", 0)
        + detect_result.get("risk_score", 0)
        + hunt_result.get("risk_score", 0)
    )

    severity = compute_severity(risk_score)

    # 5. Incident Response
    incident_result = safe_call(
        incident_response,
        {"severity": severity},
        [event]
    )

    # 6. SOAR automation
    response_result = None
    if risk_score >= 20:
        response_result = safe_call(
            process_alert,
            {},
            event,
            {"risk_score": risk_score}
        )

    alert = risk_score >= 20

    # =====================================================
    # FINAL UNIFIED SOC EVENT SCHEMA (CRITICAL FIX)
    # =====================================================
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "identity": event.get("client") or event.get("ip") or "unknown",
        "event_type": siem_result.get("event_type", "unknown"),

        "risk_score": risk_score,
        "severity": severity,
        "alert": alert,

        "stages": {
            "siem": siem_result,
            "detection": detect_result,
            "hunt": hunt_result,
            "intel": intel_result,
            "incident": incident_result,
            "soar": response_result
        }
    }

    # =====================================================
    # STATE TRACKING
    # =====================================================
    pipeline_state["events_processed"] += 1

    if alert:
        pipeline_state["alerts"].append(result)

    if incident_result:
        pipeline_state["incidents"].append(result)

    if response_result:
        pipeline_state["responses"].append(response_result)

    return result


# =========================================================
# BATCH PROCESSOR
# =========================================================
def run_pipeline(events=None):
    events = events or []
    return [process_pipeline(e) for e in events]


# =========================================================
# SOC UI STREAM CONTRACT (THIS FIXES YOUR DASHBOARD CRASH)
# =========================================================
def process_logs(logs):
    """
    Converts raw logs → UI-ready SOC stream events
    """
    output = []

    for log in logs:
        try:
            result = process_pipeline(log)

            output.append({
                "timestamp": result["timestamp"],
                "user": result["identity"],
                "event_type": result["event_type"],
                "risk_score": result["risk_score"],
                "severity": result["severity"],
                "alert": result["alert"]
            })

        except Exception:
            continue

    return output


# =========================================================
# LOG FETCHER (SAFE + RETRY FRIENDLY)
# =========================================================
def fetch_logs():
    BASE_URL = "http://127.0.0.1:5000"
    HEADERS = {"X-API-KEY": "dev-key-123"}

    try:
        r = requests.get(f"{BASE_URL}/logs", headers=HEADERS, timeout=3)

        if r.status_code != 200:
            return []

        data = r.json()

        if isinstance(data, dict):
            return data.get("logs", [])

        return data if isinstance(data, list) else []

    except Exception:
        return []


# =========================================================
# PIPELINE STATUS
# =========================================================
def get_pipeline_status():
    return {
        "events_processed": pipeline_state["events_processed"],
        "alerts": len(pipeline_state["alerts"]),
        "incidents": len(pipeline_state["incidents"]),
        "responses": len(pipeline_state["responses"])
    }


# =========================================================
# TEST ENTRYPOINT
# =========================================================
def test_main():
    sample = {
        "client": "test_user",
        "action": "unlock_vehicle",
        "vehicle_id": "V1",
        "auth": False
    }

    r = process_pipeline(sample)

    assert "risk_score" in r
    assert "severity" in r
    assert isinstance(r["risk_score"], (int, float))


# =========================================================
# CLI TEST
# =========================================================
if __name__ == "__main__":

    print("🚀 SOC PIPELINE STARTED")

    sample_events = [
        {"client": "alice", "action": "unlock_vehicle", "vehicle_id": "V999", "auth": True},
        {"client": "bob", "action": "view_vehicle", "vehicle_id": "V123", "auth": True},
    ]

    results = run_pipeline(sample_events)

    for r in results:
        print("\n--- EVENT ---")
        print("Risk:", r["risk_score"])
        print("Severity:", r["severity"])
        print("Alert:", r["alert"])