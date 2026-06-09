from datetime import datetime, timezone

from soc_scoring import compute_severity

from phase_04_siem_detection import process_event as siem_process
from phase_05_detection_engineering import analyze_event as detect_engine
from phase_06_threat_hunting import analyze_logs as threat_hunt
from phase_07_incident_response import incident_response
from phase_08_threat_intelligence_correlations import correlate_iocs


def process_pipeline(event: dict) -> dict:

    siem = siem_process(event)
    detect = detect_engine(event)
    hunt = threat_hunt([event])
    intel = correlate_iocs([event])

    siem_score = siem.get("risk_score", 0)
    detect_score = detect.get("risk_score", 0)
    hunt_score = hunt.get("risk_score", 0)

    risk_score = siem_score + detect_score + hunt_score
    severity = compute_severity(risk_score)

    incident = incident_response([event])

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,

        "stages": {
            "siem": siem,
            "detection": detect,
            "hunt": hunt,
            "intel": intel,
            "incident": incident
        },

        "risk_score": risk_score,
        "severity": severity,
        "alert": risk_score >= 20
    }