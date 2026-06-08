import requests
import json
from collections import defaultdict

from soc_scoring import compute_severity, normalize_score

BASE_URL = "http://127.0.0.1:5000"

HEADERS = {
    "X-API-KEY": "dev-key-123"
}

# -----------------------------
# ATTACK INTELLIGENCE MAP
# -----------------------------
ATTACK_MAPPING = {
    "invalid_api_key": {
        "technique": "T1078",
        "name": "Valid Accounts",
        "base_score": 40
    },
    "missing_api_key": {
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "base_score": 25
    },
    "unauthorized_vehicle_access": {
        "technique": "T1210",
        "name": "Exploitation of Remote Services",
        "base_score": 50
    }
}

# -----------------------------
# STATE (optional analytics)
# -----------------------------
identity_risk = defaultdict(int)
processed_events = set()


# =========================================================
# DETECTION ENGINE (ENRICHMENT LAYER)
# =========================================================
def analyze_event(event: dict) -> dict:
    """
    Takes SIEM output → enriches + normalizes → returns SOC-grade signal
    """

    reason = event.get("reason") or event.get("event_type")
    identity = event.get("role", "unknown")

    base = ATTACK_MAPPING.get(reason)

    # -----------------------------
    # BENIGN CASE
    # -----------------------------
    if not base:
        return {
            "risk_score": 0,
            "severity": "LOW",
            "technique": None,
            "attack": "benign_activity",
            "enriched": False
        }

    # -----------------------------
    # RAW SCORE (from mapping)
    # -----------------------------
    raw_score = base["base_score"]

    # -----------------------------
    # 🔥 NORMALIZATION STEP (CRITICAL FIX)
    # -----------------------------
    risk_score = normalize_score(raw_score)

    # -----------------------------
    # UNIFIED SEVERITY
    # -----------------------------
    severity = compute_severity(risk_score)

    # -----------------------------
    # OPTIONAL TRACKING
    # -----------------------------
    identity_risk[identity] += risk_score

    return {
        "risk_score": int(risk_score),
        "severity": severity,
        "technique": base["technique"],
        "attack": base["name"],
        "enriched": True
    }


# =========================================================
# COMPAT WRAPPER (USED BY SOC PIPELINE)
# =========================================================
def process_event(event: dict) -> dict:
    return analyze_event(event)


# =========================================================
# LOG FETCH (optional local testing)
# =========================================================
def fetch_logs():
    try:
        r = requests.get(f"{BASE_URL}/logs", headers=HEADERS, timeout=5)

        if r.status_code != 200:
            return []

        data = r.json()

        if isinstance(data, dict) and "logs" in data:
            return data["logs"]

        return data if isinstance(data, list) else []

    except Exception:
        return []


# =========================================================
# BATCH PROCESSING
# =========================================================
def process_logs(logs):
    results = []

    for log in logs:
        result = analyze_event(log)
        results.append(result)

    return results


# =========================================================
# TEST ENTRYPOINT
# =========================================================
def test_main():
    sample = {
        "reason": "invalid_api_key",
        "role": "test_user"
    }

    result = analyze_event(sample)

    assert isinstance(result, dict)
    assert "risk_score" in result
    assert "severity" in result
    assert isinstance(result["risk_score"], int)


# =========================================================
# MAIN
# =========================================================
if __name__ == "__main__":
    logs = fetch_logs()

    if logs:
        out = process_logs(logs)

        print("\n=== DETECTION ENGINE RESULTS ===")
        for o in out:
            print(o)
    else:
        print("[INFO] No logs available")