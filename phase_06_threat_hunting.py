import requests
import json
from collections import defaultdict, Counter
from datetime import datetime, timezone

BASE_URL = "http://127.0.0.1:5000"

HEADERS = {
    "X-API-KEY": "dev-key-123"
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

        print(f"[INFO] STATUS CODE: {response.status_code}")

        if response.status_code != 200:
            print("[ERROR] Failed to fetch logs")
            return []

        data = response.json()

        if isinstance(data, dict) and "logs" in data:
            logs = data["logs"]
        elif isinstance(data, list):
            logs = data
        else:
            print("[ERROR] Unexpected log format")
            return []

        print(f"[INFO] LOG COUNT: {len(logs)}")
        return logs

    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return []


# -----------------------------
# THREAT HUNTING ENGINE
# -----------------------------
def analyze_logs(logs):

    identity_activity = defaultdict(list)
    vehicle_targets = defaultdict(set)
    identity_risk = Counter()
    technique_counter = Counter()
    suspicious_clients = Counter()

    mitre_mapping = {
        "invalid_api_key": {"technique": "T1078", "risk": 40},
        "missing_api_key": {"technique": "T1190", "risk": 25},
        "unauthorized_vehicle_access": {"technique": "T1210", "risk": 50},
    }

    total_risk = 0

    # -----------------------------
    # PROCESS LOGS
    # -----------------------------
    for log in logs:

        identity = log.get("role", "unknown")
        vehicle = log.get("vehicle_id", "unknown")
        client = log.get("client", "unknown")
        reason = log.get("reason", "normal_activity")

        identity_activity[identity].append(log)

        if vehicle:
            vehicle_targets[identity].add(vehicle)

        suspicious_clients[client] += 1

        if reason in mitre_mapping:
            risk = mitre_mapping[reason]["risk"]
            technique = mitre_mapping[reason]["technique"]

            identity_risk[identity] += risk
            technique_counter[technique] += 1
            total_risk += risk

    # -----------------------------
    # PRINT RESULTS (optional UI output)
    # -----------------------------
    print("\n==============================")
    print("THREAT HUNT RESULTS")
    print("==============================")

    for identity, events in identity_activity.items():

        score = identity_risk[identity]

        print(f"\nIdentity: {identity}")
        print(f"Total Events: {len(events)}")

        print("Vehicles Targeted:")
        for vehicle in vehicle_targets[identity]:
            print(f" - {vehicle}")

        print(f"Cumulative Risk Score: {score}")

        if score >= 200:
            severity = "CRITICAL"
        elif score >= 100:
            severity = "HIGH"
        elif score >= 50:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        print(f"Severity: {severity}")

        print("\nTimeline:")
        for event in sorted(events, key=lambda x: x.get("timestamp", "")):
            print(f"[{event.get('timestamp','unknown')}] "
                  f"{event.get('endpoint','unknown')} -> "
                  f"{event.get('reason','normal_activity')}")

    # -----------------------------
    # MITRE SUMMARY
    # -----------------------------
    print("\n==============================")
    print("MITRE TECHNIQUE SUMMARY")
    print("==============================")

    for technique, count in technique_counter.items():
        print(f"{technique} : {count} event(s)")

    # -----------------------------
    # SUSPICIOUS CLIENTS
    # -----------------------------
    print("\n==============================")
    print("SUSPICIOUS CLIENT ACTIVITY")
    print("==============================")

    for client, count in suspicious_clients.items():
        if count >= 3:
            print(f"{client} -> {count} events")

    # -----------------------------
    # INCIDENT REPORT
    # -----------------------------
    incident_report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_logs": len(logs),
        "total_risk": total_risk,
        "identities": {},
        "mitre_summary": dict(technique_counter),
    }

    for identity in identity_activity:
        incident_report["identities"][identity] = {
            "risk_score": identity_risk[identity],
            "vehicles_targeted": list(vehicle_targets[identity]),
            "event_count": len(identity_activity[identity]),
        }

    filename = f"incident_report_{datetime.now().strftime('%H%M%S')}.json"

    with open(filename, "w") as f:
        json.dump(incident_report, f, indent=4)

    print("\n==============================")
    print("INCIDENT REPORT GENERATED")
    print("==============================")
    print(f"[SAVED] {filename}")

    # IMPORTANT: pipeline needs a score output
    return {
        "score": total_risk,
        "techniques": dict(technique_counter),
        "suspicious_clients": dict(suspicious_clients),
        "incident_report": incident_report
    }


# -----------------------------
# MAIN ENTRY
# -----------------------------
if __name__ == "__main__":
    logs = fetch_logs()

    if not logs:
        print("[INFO] No logs available")
    else:
        analyze_logs(logs)


# -----------------------------
# TEST ENTRYPOINT
# -----------------------------
def test_main():
    print("safe execution ok")