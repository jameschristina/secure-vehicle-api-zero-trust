import time
import threading
import uuid

from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from flask import Flask, request, jsonify

app = Flask(__name__)

# ==================================
# CONFIG
# ==================================

WINDOW_SECONDS = 60
MAX_SCORE = 100

API_KEY = "dev-key-123"

# ==================================
# ATTACK GRAPH
# ==================================

ATTACK_GRAPH = {
    "AUTH_SPIKE": [],
    "BRUTE_FORCE": ["AUTH_SPIKE"],
    "DEVICE_CHANGE": ["AUTH_SPIKE"],
    "BASELINE_DEVIATION": ["AUTH_SPIKE"],
    "PRIVILEGE_ABUSE": [
        "BRUTE_FORCE",
        "DEVICE_CHANGE"
    ],
    "VEHICLE_COMMAND_ACCESS": [
        "PRIVILEGE_ABUSE"
    ]
}

# ==================================
# STORAGE
# ==================================

event_stream = defaultdict(lambda: deque())

vehicle_profile = defaultdict(
    lambda: {
        "baseline_failures": 2,
        "device_changes": 0,
        "last_seen": None
    }
)

incidents = {}

last_alert_time = {}

# ==================================
# UTILS
# ==================================

def utc_now():
    return datetime.now(timezone.utc)

def severity(score):

    if score >= 90:
        return "CRITICAL"

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"

def suppress(vehicle):

    last = last_alert_time.get(vehicle)

    if not last:
        return False

    return (utc_now() - last).seconds < 5

def mark_alert(vehicle):
    last_alert_time[vehicle] = utc_now()

# ==================================
# LEVEL 4 RISK ENGINE
# ==================================

def calculate_risk(
    failed_count,
    device_change=False,
    privilege_abuse=False,
    command_access=False
):

    score = 0
    signals = []

    if failed_count >= 5:
        score += 40
        signals.append("AUTH_SPIKE")

    if failed_count >= 10:
        score += 20
        signals.append("BRUTE_FORCE")

    if device_change:
        score += 20
        signals.append("DEVICE_CHANGE")

    baseline = vehicle_profile["CAR456"]["baseline_failures"]

    if failed_count > baseline * 2:
        score += 10
        signals.append("BASELINE_DEVIATION")

    if privilege_abuse:
        score += 30
        signals.append("PRIVILEGE_ABUSE")

    if command_access:
        score += 40
        signals.append("VEHICLE_COMMAND_ACCESS")

    return min(score, MAX_SCORE), signals

# ==================================
# ATTACK GRAPH CORRELATION
# ==================================

def build_attack_path(signals):

    ordered = []

    for stage in ATTACK_GRAPH:

        if stage in signals:
            ordered.append(stage)

    return ordered

# ==================================
# INCIDENT ENGINE
# ==================================

def create_incident(
    vehicle,
    score,
    signals
):

    attack_path = build_attack_path(signals)

    incident = {
        "incident_id": str(uuid.uuid4()),
        "vehicle": vehicle,
        "type": "Attack Graph Correlated Threat",
        "status": "NEW",
        "first_seen": utc_now().isoformat(),
        "last_seen": utc_now().isoformat(),
        "risk_score": score,
        "severity": severity(score),
        "signals": signals,
        "attack_path": attack_path,
        "recommended_action":
            "Monitor Activity"
    }

    incidents[vehicle] = incident

    print("\n🚨 NEW INCIDENT CREATED")
    print(incident)

def update_incident(
    vehicle,
    score,
    signals
):

    incident = incidents[vehicle]

    incident["last_seen"] = utc_now().isoformat()

    incident["signals"] = list(
        set(
            incident["signals"] + signals
        )
    )

    incident["attack_path"] = build_attack_path(
        incident["signals"]
    )

    incident["risk_score"] = score
    incident["severity"] = severity(score)

    if score >= 90:
        incident["status"] = "ESCALATED"
        incident["recommended_action"] = (
            "Lock Vehicle + Force MFA"
        )

    elif score >= 70:
        incident["status"] = "ACTIVE"
        incident["recommended_action"] = (
            "SOC Investigation Required"
        )

    else:
        incident["status"] = "ACTIVE"

    print("\n🔁 INCIDENT UPDATED")
    print(incident)

# ==================================
# STREAM PROCESSOR
# ==================================

def process_event(
    vehicle,
    failed_auth=True,
    device_change=False,
    privilege_abuse=False,
    command_access=False
):

    ts = utc_now()

    stream = event_stream[vehicle]

    stream.append(ts)

    cutoff = ts - timedelta(
        seconds=WINDOW_SECONDS
    )

    while stream and stream[0] < cutoff:
        stream.popleft()

    failed_count = len(stream)

    score, signals = calculate_risk(
        failed_count,
        device_change,
        privilege_abuse,
        command_access
    )

    if score == 0:
        return

    if vehicle not in incidents:
        create_incident(
            vehicle,
            score,
            signals
        )

    else:
        update_incident(
            vehicle,
            score,
            signals
        )

# ==================================
# ATTACK SIMULATION
# ==================================

def simulator():

    vehicle = "CAR456"

    for i in range(1, 25):

        device_change = False
        privilege_abuse = False
        command_access = False

        if i == 8:
            device_change = True

        if i == 15:
            privilege_abuse = True

        if i == 20:
            command_access = True

        process_event(
            vehicle,
            True,
            device_change,
            privilege_abuse,
            command_access
        )

        time.sleep(1)

# ==================================
# API
# ==================================

@app.route("/")
def root():
    return jsonify({
        "engine": "SOC Level 4 Attack Graph",
        "status": "running"
    })

@app.route("/status")
def status():

    key = request.headers.get(
        "X-API-KEY"
    )

    if key != API_KEY:
        return jsonify({
            "error": "unauthorized"
        }), 401

    vehicle = request.args.get(
        "vehicle_id"
    )

    incident = incidents.get(vehicle)

    if not incident:
        return jsonify({
            "vehicle": vehicle,
            "status": "clean"
        })

    return jsonify(incident)

@app.route("/incidents")
def all_incidents():

    key = request.headers.get(
        "X-API-KEY"
    )

    if key != API_KEY:
        return jsonify({
            "error": "unauthorized"
        }), 401

    return jsonify(
        list(
            incidents.values()
        )
    )

# ==================================
# MAIN
# ==================================

if __name__ == "__main__":

    print(
        "\n=== SOC LEVEL 4 ATTACK GRAPH ENGINE RUNNING ===\n"
    )

    threading.Thread(
        target=simulator,
        daemon=True
    ).start()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )