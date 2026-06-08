import requests
import json
from collections import defaultdict, Counter
from datetime import datetime, timezone
import time

from soc_scoring import compute_severity, normalize_score

BASE_URL = "http://127.0.0.1:5000"

HEADERS = {
    "X-API-KEY": "dev-key-123"
}

# -----------------------------
# MITRE ATT&CK MAPPING
# -----------------------------
MITRE_MAPPING = {
    "invalid_api_key": {
        "technique": "T1078",
        "attack": "Valid Accounts",
        "risk": 40
    },
    "missing_api_key": {
        "technique": "T1190",
        "attack": "Exploit Public-Facing Application",
        "risk": 25
    },
    "unauthorized_vehicle_access": {
        "technique": "T1210",
        "attack": "Exploitation of Remote Services",
        "risk": 50
    }
}


# -----------------------------
# FETCH LOGS
# -----------------------------
def fetch_logs():
    try:
        response = requests.get(
            f"{BASE_URL}/logs",
            headers=HEADERS,
            timeout=5
        )

        if response.status_code != 200:
            return []

        data = response.json()

        if isinstance(data, dict) and "logs" in data:
            return data["logs"]

        return data if isinstance(data, list) else []

    except Exception:
        return []


# -----------------------------
# INCIDENT RESPONSE ENGINE
# -----------------------------
def incident_response(logs):

    identity_risk = Counter()
    identity_events = defaultdict(list)
    blocked_identities = set()

    # -----------------------------
    # PROCESS LOGS
    # -----------------------------
    for log in logs:

        identity = log.get("role", "unknown")
        reason = log.get("reason")
        vehicle = log.get("vehicle_id")
        timestamp = log.get("timestamp")

        identity_events[identity].append(log)

        if reason in MITRE_MAPPING:

            base = MITRE_MAPPING[reason]

            identity_risk[identity] += base["risk"]

            print("\n==============================")
            print("[SECURITY EVENT]")
            print("==============================")

            print(f"Time: {timestamp}")
            print(f"Identity: {identity}")
            print(f"Vehicle: {vehicle}")
            print(f"Reason: {reason}")
            print(f"MITRE Technique: {base['technique']}")
            print(f"Attack Name: {base['attack']}")
            print(f"Risk Added: {base['risk']}")

            print(f"Cumulative Raw Risk: {identity_risk[identity]}")

    # -----------------------------
    # SOC INCIDENT REVIEW
    # -----------------------------
    print("\n==============================")
    print("SOC INCIDENT REVIEW")
    print("==============================")

    for identity, raw_score in identity_risk.items():

        # 🔥 UNIFIED SCORING (CRITICAL FIX)
        score = normalize_score(raw_score)
        severity = compute_severity(score)

        print(f"\nIdentity: {identity}")
        print(f"Risk Score: {score}")
        print(f"Severity: {severity}")

        # -----------------------------
        # RESPONSE LOGIC (NO HARD THRESHOLDS)
        # -----------------------------
        if severity == "CRITICAL":

            blocked_identities.add(identity)

            print("\n[CONTAINMENT ACTION]")
            print(f"Identity '{identity}' BLOCKED")
            print("Action: Disable API key immediately")

        elif severity == "HIGH":

            print("\n[ESCALATION]")
            print(f"Identity '{identity}' escalated to analyst")

        elif severity == "MEDIUM":

            print("\n[MONITORING]")
            print(f"Identity '{identity}' flagged for monitoring")

    # -----------------------------
    # INCIDENT REPORT EXPORT
    # -----------------------------
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "blocked_identities": list(blocked_identities),
        "incidents": []
    }

    for identity, raw_score in identity_risk.items():

        score = normalize_score(raw_score)
        severity = compute_severity(score)

        report["incidents"].append({
            "identity": identity,
            "risk_score": score,
            "severity": severity,
            "event_count": len(identity_events[identity]),
            "events": identity_events[identity]
        })

    filename = f"soc_incident_report_{datetime.now().strftime('%H%M%S')}.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print("\n==============================")
    print("INCIDENT REPORT GENERATED")
    print("==============================")
    print(f"[SAVED] {filename}")

    return report


# -----------------------------
# HEARTBEAT MONITOR
# -----------------------------
def heartbeat():

    while True:

        current_time = datetime.now().strftime("%H:%M:%S")

        print(f"\n[HEARTBEAT] {current_time} | SOC monitoring active...")

        logs = fetch_logs()

        if logs:
            incident_response(logs)
        else:
            print("[INFO] No logs available")

        time.sleep(15)


# -----------------------------
# TEST ENTRYPOINT
# -----------------------------
def test_main():
    sample_logs = [
        {"role": "alice", "reason": "invalid_api_key"},
        {"role": "bob", "reason": "missing_api_key"}
    ]

    result = incident_response(sample_logs)

    assert isinstance(result, dict)
    assert "incidents" in result
    assert "blocked_identities" in result


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    print("\n==============================")
    print("PHASE 7 INCIDENT RESPONSE")
    print("==============================")

    heartbeat()