import requests
import json
import time
from collections import defaultdict
from datetime import datetime

BASE_URL = "http://127.0.0.1:5000"

HEADERS = {
    "X-API-KEY": "dev-key-123"
}

# -----------------------------
# RISK MODEL
# -----------------------------
RISK_WEIGHTS = {
    "missing_api_key": 5,
    "invalid_api_key": 10,
    "unauthorized_vehicle_access": 20,
    "rate_limited": 8,
    "not_found": 3,
    "success": 0
}

ALERT_THRESHOLD = 20
POLL_INTERVAL = 3

# -----------------------------
# STATE
# -----------------------------
identity_events = defaultdict(list)
identity_scores = defaultdict(int)
seen_logs = set()

alert_cache = {}
ALERT_COOLDOWN = 15


# =========================================================
# 🧠 CORE SIEM ENGINE (TESTABLE LOGIC)
# =========================================================
def analyze_event(log: dict) -> dict:
    action = log.get("action")
    vehicle_id = log.get("vehicle_id")
    auth = log.get("auth", False)
    success = log.get("success", False)
    reason = log.get("failure_reason") or log.get("reason")

    # -------------------------
    # SUCCESS CASE
    # -------------------------
    if success is True:
        return {
            "alert_generated": False,
            "severity": 0,
            "risk_score": 0,
            "event_type": "success"
        }

    alert = False
    severity = 0
    event_type = "normal"

    # -------------------------
    # DETECTION RULES
    # -------------------------

    # highest confidence rule
    if action == "unlock_vehicle" and vehicle_id == "V999":
        alert = True
        severity = 10
        event_type = "unauthorized_access"

    elif auth is False:
        alert = True
        severity = 7
        event_type = "unauthenticated_access"

    elif reason == "invalid_api_key":
        alert = True
        severity = 8
        event_type = "invalid_api_key"

    elif reason == "missing_api_key":
        alert = True
        severity = 6
        event_type = "missing_api_key"

    elif reason == "rate_limited":
        alert = True
        severity = 5
        event_type = "rate_limited"

    # -------------------------
    # DEFAULT CASE (IMPORTANT FIX)
    # -------------------------
    else:
        alert = False
        severity = 0   # ✅ FIXED (was 1)
        event_type = "normal"

    return {
        "alert_generated": alert,
        "severity": severity,
        "risk_score": severity * 10,
        "event_type": event_type
    }


# =========================================================
# COMPATIBILITY WRAPPER (USED BY TESTS)
# =========================================================
def process_event(event: dict) -> dict:
    return analyze_event(event)


# -----------------------------
# FETCH LOGS
# -----------------------------
def fetch_logs():
    try:
        r = requests.get(f"{BASE_URL}/logs", headers=HEADERS)

        if r.status_code != 200:
            return []

        if not r.text.strip():
            return []

        data = r.json()

        if isinstance(data, dict) and "logs" in data:
            data = data["logs"]

        return data if isinstance(data, list) else []

    except Exception as e:
        print(f"[ERROR] {e}")
        return []


# -----------------------------
# NORMALIZE
# -----------------------------
def normalize(log):
    if isinstance(log, str):
        try:
            return json.loads(log)
        except:
            return None
    return log if isinstance(log, dict) else None


# -----------------------------
# IDENTITY RESOLUTION
# -----------------------------
def get_identity(log):
    client = log.get("client") or log.get("ip") or "unknown"
    vehicle = log.get("vehicle_id") or "unknown"
    return f"{client}|{vehicle}"


# -----------------------------
# PROCESS LOGS
# -----------------------------
def process_logs(logs):
    new_events = 0

    for raw in logs:
        log = normalize(raw)
        if not log:
            continue

        fingerprint = json.dumps(log, sort_keys=True)
        if fingerprint in seen_logs:
            continue

        seen_logs.add(fingerprint)
        new_events += 1

        identity = get_identity(log)

        result = analyze_event(log)
        score = result["risk_score"]

        identity_events[identity].append(log)
        identity_scores[identity] += score

    return new_events


# -----------------------------
# ALERT COOLDOWN
# -----------------------------
def should_alert(identity):
    now = time.time()

    if identity in alert_cache:
        if now - alert_cache[identity] < ALERT_COOLDOWN:
            return False

    alert_cache[identity] = now
    return True


# -----------------------------
# ALERT ENGINE
# -----------------------------
def trigger_alert(identity):
    score = identity_scores[identity]
    events = identity_events[identity]

    severity = (
        "CRITICAL" if score >= 100 else
        "HIGH" if score >= 60 else
        "MEDIUM" if score >= 30 else
        "LOW"
    )

    print("\n🚨 SIEM ALERT 🚨")
    print(f"Time: {datetime.now().strftime('%H:%M:%S')}")
    print(f"Identity: {identity}")
    print(f"Severity: {severity}")
    print(f"Risk Score: {float(score)}")
    print(f"Events: {len(events)}")
    print("-" * 50)


# -----------------------------
# SNAPSHOT
# -----------------------------
def snapshot():
    print("\n--- LIVE SIEM SNAPSHOT ---")

    if not identity_scores:
        print("[INFO] No identities detected.")
        return

    for identity, score in identity_scores.items():
        print(f"{identity} | Score: {float(score)} | Events: {len(identity_events[identity])}")


# -----------------------------
# TEST HARNESS ENTRY (REQUIRED BY CI)
# -----------------------------
def test_main():
    sample_event = {
        "action": "unlock_vehicle",
        "vehicle_id": "V123",
        "auth": False
    }

    result = analyze_event(sample_event)

    assert isinstance(result, dict)
    assert "alert_generated" in result
    assert "severity" in result
    assert result["severity"] >= 0


# -----------------------------
# LIVE SIEM LOOP (DAEMON MODE)
# -----------------------------
def run():
    print("\n🧠 STARTING SIEM v4.1 — ACTIVE MODE\n")

    while True:
        logs = fetch_logs()
        new_events = process_logs(logs)

        print(f"\n[METRICS] New Events: {new_events} | "
              f"Identities: {len(identity_scores)} | "
              f"Total Events: {sum(len(v) for v in identity_events.values())}")

        for identity in identity_scores:
            if identity_scores[identity] >= ALERT_THRESHOLD:
                if should_alert(identity):
                    trigger_alert(identity)

        snapshot()

        print(f"\n[HEARTBEAT] {datetime.now().strftime('%H:%M:%S')}")
        time.sleep(POLL_INTERVAL)


# -----------------------------
# ENTRY POINT
# -----------------------------
if __name__ == "__main__":
    run()