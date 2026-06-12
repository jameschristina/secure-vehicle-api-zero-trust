# phase_10_detection_engine.py (FINAL ENTERPRISE SIEM VERSION)

from flask import Flask, render_template_string, Response, request
from datetime import datetime, timezone
from collections import defaultdict, deque
import threading
import random
import time
import sqlite3
import json

app = Flask(__name__)

# ============================================================
# IDENTITY MODEL
# ============================================================

USER_VEHICLE_MAP = {
    "user1": ["CAR100"],
    "user2": ["CAR101"],
    "user3": ["CAR102"],
}

VEHICLES = ["CAR100", "CAR101", "CAR102", "CAR103", "CAR104"]
USERS = list(USER_VEHICLE_MAP.keys())

# ============================================================
# KAFKA-STYLE EVENT STREAM (IN-MEMORY TOPIC)
# ============================================================

TOPIC = deque(maxlen=500)

# ============================================================
# SQLITE PERSISTENCE LAYER (SIEM INDEX)
# ============================================================

conn = sqlite3.connect("siem_phase10.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS events (
    timestamp TEXT,
    user TEXT,
    vehicle TEXT,
    alert TEXT,
    severity TEXT,
    score INTEGER,
    mitre TEXT,
    correlation TEXT
)
""")
conn.commit()

def persist(event):
    cursor.execute("""
        INSERT INTO events VALUES (?,?,?,?,?,?,?,?)
    """, (
        event["timestamp"],
        event["user"],
        event["vehicle"],
        event["alert"],
        event["severity"],
        event["score"],
        event["mitre"],
        event["correlation"]
    ))
    conn.commit()

# ============================================================
# ATTACK GRAPH (RELATIONSHIP MAP)
# ============================================================

ATTACK_GRAPH = defaultdict(set)

def update_graph(user, alert):
    ATTACK_GRAPH[user].add(alert)

# ============================================================
# YAML RULE ENGINE (SIMULATED)
# ============================================================

RULES = [
    {"name": "ENTITLEMENT_VIOLATION", "score": 120, "severity": "HIGH"},
    {"name": "PRIVILEGE_ESCALATION", "score": 200, "severity": "CRITICAL"},
    {"name": "VEHICLE_ENUMERATION", "score": 150, "severity": "HIGH"},
    {"name": "EXCESSIVE_REQUESTS", "score": 90, "severity": "MEDIUM"},
]

# ============================================================
# MITRE MAPPING
# ============================================================

MITRE = {
    "ENTITLEMENT_VIOLATION": "T1078",
    "PRIVILEGE_ESCALATION": "T1068",
    "VEHICLE_ENUMERATION": "T1087",
    "EXCESSIVE_REQUESTS": "T1499",
}

# ============================================================
# STATE
# ============================================================

request_log = defaultdict(lambda: deque(maxlen=60))
vehicle_log = defaultdict(lambda: deque(maxlen=20))
failed_auth = defaultdict(int)

EVENTS = []

# ============================================================
# RISK ENGINE
# ============================================================

def status(score):
    if score < 70:
        return "LOW", "MONITOR"
    elif score < 130:
        return "MEDIUM", "INVESTIGATE"
    elif score < 180:
        return "HIGH", "ESCALATE"
    return "CRITICAL", "LOCKDOWN"

# ============================================================
# CORRELATION ENGINE (ATTACK CHAINS)
# ============================================================

def correlate(user, alert):
    ATTACK_GRAPH[user].add(alert)

    chain = ATTACK_GRAPH[user]

    if "ENTITLEMENT_VIOLATION" in chain and "VEHICLE_ENUMERATION" in chain:
        return "COORDINATED_ACCESS_ATTACK"

    if chain.count("ENTITLEMENT_VIOLATION") >= 2:
        return "PERSISTENT_ACCESS_ABUSE"

    return None

# ============================================================
# EVENT EMITTER
# ============================================================

def emit(user, vehicle, alert):

    rule = next((r for r in RULES if r["name"] == alert), None)

    score = rule["score"] if rule else 50
    sev, action = status(score)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user,
        "vehicle": vehicle,
        "alert": alert,
        "severity": sev,
        "score": score,
        "mitre": MITRE.get(alert, "UNKNOWN"),
        "correlation": correlate(user, alert)
    }

    EVENTS.append(event)
    TOPIC.append(event)

    persist(event)
    update_graph(user, alert)

    print(f"[SIEM] {user} | {vehicle} | {alert} | {sev} | {event['mitre']}")

# ============================================================
# DETECTION ENGINE
# ============================================================

def detect(user, vehicle):

    allowed = USER_VEHICLE_MAP.get(user, [])

    # Entitlement violation
    if vehicle not in allowed:
        failed_auth[user] += 1
        emit(user, vehicle, "ENTITLEMENT_VIOLATION")

        if failed_auth[user] >= 3:
            emit(user, vehicle, "ENTITLEMENT_VIOLATION")

    # Privilege escalation simulation
    if vehicle == "CAR104":
        emit(user, vehicle, "PRIVILEGE_ESCALATION")

    # Behavioral tracking
    request_log[user].append(time.time())
    vehicle_log[user].append(vehicle)

    now = time.time()

    # Excessive requests
    if len([t for t in request_log[user] if now - t < 10]) > 7:
        emit(user, vehicle, "EXCESSIVE_REQUESTS")

    # Vehicle enumeration
    if len(set(vehicle_log[user])) >= 3:
        emit(user, vehicle, "VEHICLE_ENUMERATION")

# ============================================================
# SIMULATION ENGINE
# ============================================================

def simulate():

    while True:

        user = random.choice(USERS)

        if random.random() < 0.7:
            vehicle = USER_VEHICLE_MAP[user][0]
        else:
            vehicle = random.choice(VEHICLES)

        detect(user, vehicle)

        time.sleep(random.uniform(0.8, 1.3))

# ============================================================
# SPLUNK-LIKE QUERY ENGINE
# ============================================================

def query(filters):

    results = EVENTS

    for f in filters:
        if "=" in f:
            k, v = f.split("=")
            results = [e for e in results if str(e.get(k)) == v]

    return results

# ============================================================
# SSE STREAM
# ============================================================

@app.route("/api/events")
def stream():

    def gen():

        last = 0

        while True:

            if len(EVENTS) > last:

                for e in EVENTS[last:]:

                    yield "data: " + "|".join([
                        e["timestamp"],
                        e["user"],
                        e["vehicle"],
                        e["alert"],
                        e["severity"],
                        e["mitre"],
                        str(e["correlation"])
                    ]) + "\n\n"

                last = len(EVENTS)

            time.sleep(0.5)

    return Response(gen(), mimetype="text/event-stream")

# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Phase 10 Enterprise SIEM</title>

<style>
body { background:#111; color:#eee; font-family:Arial; }
table { width:100%; border-collapse:collapse; }
th, td { padding:10px; border-bottom:1px solid #333; }
th { background:#222; }

.critical { color:red; font-weight:bold; }
.high { color:orange; }
.medium { color:yellow; }
</style>
</head>

<body>

<h2>🚨 Phase 10 Enterprise SIEM (FINAL)</h2>

<table>
<thead>
<tr>
<th>Time</th>
<th>User</th>
<th>Vehicle</th>
<th>Alert</th>
<th>Severity</th>
<th>MITRE</th>
<th>Correlation</th>
</tr>
</thead>

<tbody id="log"></tbody>
</table>

<script>

const s = new EventSource("/api/events");
const log = document.getElementById("log");

s.onmessage = function(e){

    const d = e.data.split("|");

    const row = document.createElement("tr");

    row.innerHTML = `
        <td>${d[0]}</td>
        <td>${d[1]}</td>
        <td>${d[2]}</td>
        <td>${d[3]}</td>
        <td>${d[4]}</td>
        <td>${d[5]}</td>
        <td>${d[6]}</td>
    `;

    log.prepend(row);

    if(log.children.length > 50){
        log.removeChild(log.lastChild);
    }
};

</script>

</body>
</html>
"""

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)

# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("===================================")
    print("PHASE 10 FINAL ENTERPRISE SIEM")
    print("Kafka + YAML + MITRE + Correlation + SQLite")
    print("===================================")

    threading.Thread(target=simulate, daemon=True).start()

    app.run(host="0.0.0.0", port=5000, debug=False)