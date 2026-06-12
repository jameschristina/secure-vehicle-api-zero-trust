# phase_10_detection_engine.py (FINAL FIXED VERSION)

from flask import Flask, render_template_string, Response
from datetime import datetime, timezone
from collections import defaultdict, deque
import threading
import random
import time

app = Flask(__name__)

# ============================================================
# IDENTITY MODEL
# ============================================================

USER_VEHICLE_MAP = {
    "user1": ["CAR100"],
    "user2": ["CAR101"],
    "user3": ["CAR102"],
}

USERS = list(USER_VEHICLE_MAP.keys())
VEHICLES = ["CAR100", "CAR101", "CAR102", "CAR103", "CAR104"]

# ============================================================
# EVENT STORE
# ============================================================

EVENTS = []

# ============================================================
# STATE TRACKING
# ============================================================

failed_auth = defaultdict(int)
request_log = defaultdict(lambda: deque(maxlen=60))
vehicle_log = defaultdict(lambda: deque(maxlen=20))

# ============================================================
# ATTACK GRAPH (FIXED)
# ============================================================

ATTACK_GRAPH = defaultdict(list)

def update_graph(user, alert):
    ATTACK_GRAPH[user].append(alert)
    if len(ATTACK_GRAPH[user]) > 25:
        ATTACK_GRAPH[user].pop(0)

def correlate(user, alert):

    update_graph(user, alert)
    chain = ATTACK_GRAPH[user]

    if "ENTITLEMENT_VIOLATION" in chain and "VEHICLE_ENUMERATION" in chain:
        return "COORDINATED_ACCESS_ATTACK"

    if chain.count("ENTITLEMENT_VIOLATION") >= 2:
        return "PERSISTENT_ACCESS_ABUSE"

    return None

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
# ALERT EMITTER
# ============================================================

def emit(user, vehicle, alert):

    scores = {
        "ENTITLEMENT_VIOLATION": 120,
        "PRIVILEGE_ESCALATION": 200,
        "VEHICLE_ENUMERATION": 150,
        "EXCESSIVE_REQUESTS": 90,
    }

    score = scores.get(alert, 50)
    sev, action = status(score)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user,
        "vehicle": vehicle,
        "alert": alert,
        "severity": sev,
        "action": action,
        "score": score,
        "mitre": {
            "ENTITLEMENT_VIOLATION": "T1078",
            "PRIVILEGE_ESCALATION": "T1068",
            "VEHICLE_ENUMERATION": "T1087",
            "EXCESSIVE_REQUESTS": "T1499",
        }.get(alert, "UNKNOWN"),
        "correlation": correlate(user, alert)
    }

    EVENTS.append(event)

# ============================================================
# DETECTION ENGINE
# ============================================================

def detect(user, vehicle):

    allowed = USER_VEHICLE_MAP.get(user, [])

    # Entitlement violation
    if vehicle not in allowed:
        failed_auth[user] += 1
        emit(user, vehicle, "ENTITLEMENT_VIOLATION")

    # Privilege escalation simulation
    if vehicle == "CAR104":
        emit(user, vehicle, "PRIVILEGE_ESCALATION")

    # Behavior tracking
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

        time.sleep(random.uniform(0.8, 1.2))

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
<title>Phase 10 SOC Dashboard</title>

<style>
body { background:#0b0f14; color:#e6e6e6; font-family:Arial; }
table { width:100%; border-collapse:collapse; }
th, td { padding:10px; border-bottom:1px solid #222; }
th { background:#111; }

.low { color:#2dd4bf; }
.medium { color:#ffd60a; }
.high { color:#ff9f1a; }
.critical { color:#ff4d4d; font-weight:bold; }
</style>
</head>

<body>

<h2>🚨 Phase 10 SOC Dashboard (LIVE)</h2>

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

const source = new EventSource("/api/events");
const log = document.getElementById("log");

source.onmessage = function(e){

    const d = e.data.split("|");

    const row = document.createElement("tr");

    row.innerHTML = `
        <td>${d[0]}</td>
        <td>${d[1]}</td>
        <td>${d[2]}</td>
        <td>${d[3]}</td>
        <td class="${d[4].toLowerCase()}">${d[4]}</td>
        <td>${d[5]}</td>
        <td>${d[6]}</td>
    `;

    log.prepend(row);

    if(log.children.length > 60){
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
    print("PHASE 10 DETECTION ENGINE ONLINE")
    print("SOC STREAM + CORRELATION + MITRE")
    print("===================================")

    threading.Thread(target=simulate, daemon=True).start()

    app.run(host="0.0.0.0", port=5000, debug=False)