from flask import Flask, jsonify
from collections import defaultdict, deque
from datetime import datetime, timezone
import threading
import time
import uuid

app = Flask(__name__)

# =========================
# IMMUTABLE EVENT STORE
# =========================

EVENT_STORE = []

VEHICLE = "CAR456"

SIGNAL_GRAPH = defaultdict(set)


# =========================
# SAFE EVENT FACTORY
# =========================

def now():
    return datetime.now(timezone.utc)


def create_event(signal):
    return {
        "event_id": str(uuid.uuid4()),
        "vehicle": VEHICLE,
        "signal": signal,
        "timestamp": now(),
        "risk_delta": 0
    }


# =========================
# RISK ENGINE
# =========================

RISK_WEIGHTS = {
    "AUTH_SPIKE": 10,
    "DEVICE_CHANGE": 20,
    "VEHICLE_COMMAND_ACCESS": 40,
    "BASELINE_DEVIATION": 25,
    "BRUTE_FORCE": 35,
    "PRIVILEGE_ABUSE": 50
}


def compute_risk(events):
    return sum(RISK_WEIGHTS.get(e["signal"], 5) for e in events)


# =========================
# GRAPH ENGINE
# =========================

def update_graph(events):
    for i in range(1, len(events)):
        a = events[i - 1]["signal"]
        b = events[i]["signal"]
        SIGNAL_GRAPH[a].add(b)
        SIGNAL_GRAPH[b].add(a)


def correlated_paths(events):
    paths = []
    for i in range(len(events)):
        path = "→".join(e["signal"] for e in events[: i + 1])
        if len(path) > 0:
            paths.append(path)
    return paths


def graph_degree():
    return {k: len(v) for k, v in SIGNAL_GRAPH.items()}


# =========================
# SNAPSHOT BUILDER
# =========================

def build_snapshot(events):
    signals = list(dict.fromkeys(e["signal"] for e in events))

    risk = compute_risk(events)

    if risk < 30:
        severity = "LOW"
        action = "MONITOR"
    elif risk < 80:
        severity = "MEDIUM"
        action = "MONITOR"
    elif risk < 140:
        severity = "HIGH"
        action = "SOC INVESTIGATION"
    else:
        severity = "CRITICAL"
        action = "IMMEDIATE LOCKDOWN"

    predicted_next = "PRIVILEGE_ABUSE" if risk > 40 else None
    confidence = 0.75 if risk > 40 else 0.0

    update_graph(events)

    return {
        "vehicle": VEHICLE,
        "risk_score": risk,
        "signals": signals,
        "status": "ACTIVE",
        "severity": severity,
        "predicted_next": predicted_next,
        "confidence": confidence,
        "recommended_action": action,
        "event_count": len(events),
        "correlated_signals": correlated_paths(events),
        "graph_degree": graph_degree(),
        "last_event_time": events[-1]["timestamp"].isoformat()
    }


# =========================
# IMMUTABLE PROCESSOR
# =========================

def process_signal(signal):
    event = create_event(signal)
    EVENT_STORE.append(event)

    snapshot = build_snapshot(EVENT_STORE)

    print("\n🔁 LEVEL 12 SNAPSHOT:")
    print(snapshot)

    return snapshot


# =========================
# SIMULATOR (ATTACK FLOW)
# =========================

ATTACK_SEQUENCE = [
    "AUTH_SPIKE",
    "DEVICE_CHANGE",
    "VEHICLE_COMMAND_ACCESS",
    "BASELINE_DEVIATION",
    "BRUTE_FORCE",
    "PRIVILEGE_ABUSE"
]


def simulator():
    for sig in ATTACK_SEQUENCE:
        time.sleep(1)
        process_signal(sig)


# =========================
# API
# =========================

@app.route("/")
def index():
    return jsonify({
        "status": "SOC LEVEL 12 IMMUTABLE ENGINE RUNNING",
        "events": len(EVENT_STORE)
    })


# =========================
# MAIN
# =========================

if __name__ == "__main__":
    print("\n=== FINALIZED IMMUTABLE SOC ENGINE (LEVEL 12 CORE) ===\n")

    t = threading.Thread(target=simulator, daemon=True)
    t.start()

    app.run(host="0.0.0.0", port=5000, debug=False)