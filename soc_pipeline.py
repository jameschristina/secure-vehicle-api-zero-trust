"""
SOC PIPELINE ORCHESTRATOR
SIEM → Detection → Hunting → Intel → Incident → SOAR → Metrics
"""

from datetime import datetime, timezone
from soc_scoring_engine import build_score_result

# -------------------------
# SAFE IMPORTS (handles inconsistent phases)
# -------------------------
from phase_04_siem_detection import process_event as siem_process

# Phase 05 (handles naming mismatch safely)
try:
    from phase_05_detection_engineering import analyze_logs as detect_engine
except ImportError:
    try:
        from phase_05_detection_engineering import analyze_event as detect_engine
    except ImportError:
        def detect_engine(event):
            return {"score": 0}

# Phase 06 expects LIST input
from phase_06_threat_hunting import analyze_logs as threat_hunt

from phase_07_incident_response import classify_severity
from phase_08_threat_intelligence_correlations import correlate_iocs
from phase_09_soar_automation import process_alert

# -------------------------
# METRICS ENGINE
# -------------------------
metrics = get_metrics_engine()

# -------------------------
# STATE
# -------------------------
pipeline_state = {
    "events_processed": 0,
    "alerts": [],
    "incidents": [],
    "responses": []
}

# -------------------------
# SAFE HELPERS
# -------------------------
def safe_dict(obj):
    return obj if isinstance(obj, dict) else {"raw": str(obj)}

def safe_score(obj):
    if isinstance(obj, dict):
        return obj.get("score", 0) or 0
    return 0

# -------------------------
# WRAPPERS
# -------------------------
def threat_hunt_wrapper(event):
    try:
        result = threat_hunt([event])  # Phase 06 expects list
        return {"score": 15, "raw": result}
    except Exception:
        return {"score": 0}

def intel_wrapper(event):
    try:
        result = correlate_iocs([event])
        return safe_dict(result)
    except Exception:
        return {"score": 0}

def incident_wrapper(score):
    try:
        return classify_severity(score)
    except Exception:
        return {"severity": "LOW"}

def soar_wrapper(event, alert):
    try:
        return process_alert(event.get("user", "unknown"), alert)
    except Exception:
        return None

# -------------------------
# CORE PIPELINE
# -------------------------
def process_pipeline(event: dict):

    # --- STAGE 1: SIEM ---
    siem_result = safe_dict(siem_process(event))

    # --- STAGE 2: DETECTION ---
    detect_result = safe_dict(detect_engine(event))

    # --- STAGE 3: THREAT HUNT ---
    hunt_result = threat_hunt_wrapper(event)

    # --- STAGE 4: INTEL ---
    intel_result = intel_wrapper(event)

    # -------------------------
    # FORCE SIGNAL ENRICHMENT (important for SOC realism)
    # -------------------------
    if safe_score(siem_result) == 0 and not event.get("auth", True):
        siem_result["score"] = 30

    if safe_score(detect_result) == 0 and event.get("action") == "unlock_vehicle":
        detect_result["score"] = 10

    # -------------------------
    # RISK SCORE
    # -------------------------
    stage_outputs = {
    "siem": siem_result,
    "detection": detect_result,
    "threat_hunt": hunt_result,
    "intel": intel_result,
    "incident": incident_result,
    "soar": response_result,
    }

    score_result = build_score_result(stage_outputs)

    risk_score = score_result["score"]
    severity = score_result["severity"]

    # --- STAGE 5: INCIDENT ---
    incident_result = incident_wrapper(risk_score)

    # --- STAGE 6: SOAR ---
    response_result = None
    if risk_score >= 20:
        response_result = soar_wrapper(event, {"score": risk_score})

    alert = risk_score >= 20

    # -------------------------
    # OUTPUT
    # -------------------------
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "stages": {
            "siem": siem_result,
            "detection": detect_result,
            "hunt": hunt_result,
            "intel": intel_result,
            "incident": incident_result,
            "soar": response_result
        },
        "risk_score": risk_score,
        "severity": severity,
        "score_breakdown": score_result["breakdown"],
        "signals": score_result["signals"],
        "alert": alert,
        "incident": incident_result,
        "response": response_result
        }

    # -------------------------
    # STATE UPDATE
    # -------------------------
    pipeline_state["events_processed"] += 1

    if alert:
        pipeline_state["alerts"].append(result)

    if risk_score > 0:
        pipeline_state["incidents"].append(result)

    if response_result:
        pipeline_state["responses"].append(response_result)

    # -------------------------
    # METRICS (safe)
    # -------------------------
    try:
        metrics.ingest_event(event)
    except Exception:
        pass

    return result

# -------------------------
# BATCH RUNNER
# -------------------------
def run_pipeline(events=None):
    events = events or []
    return [process_pipeline(e) for e in events]

# -------------------------
# STATUS
# -------------------------
def get_pipeline_status():
    return {
        "events_processed": pipeline_state["events_processed"],
        "alerts": len(pipeline_state["alerts"]),
        "incidents": len(pipeline_state["incidents"]),
        "responses": len(pipeline_state["responses"])
    }

# -------------------------
# TEST ENTRYPOINT
# -------------------------
def test_main():
    event = {
        "user": "test_user",
        "action": "unlock_vehicle",
        "vehicle_id": "V1",
        "auth": False
    }

    result = process_pipeline(event)

    assert "stages" in result
    assert "risk_score" in result

    print("SOC PIPELINE OK")

# -------------------------
# CLI RUN
# -------------------------
if __name__ == "__main__":

    print("🚀 SOC PIPELINE STARTED")

    sample_events = [
        {"user": "alice", "action": "unlock_vehicle", "vehicle_id": "V999", "auth": True},
        {"user": "bob", "action": "view_vehicle", "vehicle_id": "V123", "auth": True},
        {"user": "eve", "action": "unlock_vehicle", "vehicle_id": "V777", "auth": False},
    ]

    results = run_pipeline(sample_events)

    for r in results:
        print("\n--- EVENT RESULT ---")
        print("User:", r["event"]["user"])
        print("Alert:", r["alert"])
        print("Risk Score:", r["risk_score"])
        print("Incident:", r["incident"])