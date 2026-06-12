# phase_10_detection_engine.py

from flask import Flask, render_template_string, Response
from datetime import datetime, timezone
from collections import defaultdict, deque
import threading
import random
import time

app = Flask(__name__)

# ============================================================
# Identity & Authorization Model
# ============================================================

USER_VEHICLE_MAP = {
    "user1": ["CAR100"],
    "user2": ["CAR101"],
    "user3": ["CAR102"],
}

ALL_VEHICLES = [
    "CAR100",
    "CAR101",
    "CAR102",
    "CAR103",
    "CAR104"
]

USERS = list(USER_VEHICLE_MAP.keys())

# ============================================================
# Detection State
# ============================================================

EVENTS = []

failed_auth_tracker = defaultdict(int)
request_tracker = defaultdict(lambda: deque(maxlen=60))
vehicle_tracker = defaultdict(lambda: deque(maxlen=20))

MAX_EVENTS = 100

# ============================================================
# Risk Engine
# ============================================================

def get_status_action(risk):
    if risk < 30:
        return "LOW", "MONITOR"
    elif risk < 70:
        return "MEDIUM", "MONITOR"
    elif risk < 130:
        return "HIGH", "SOC INVESTIGATION"
    else:
        return "CRITICAL", "IMMEDIATE LOCKDOWN"


def create_alert(user, vehicle, alert_type, risk):

    status, action = get_status_action(risk)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user,
        "vehicle": vehicle,
        "alert_type": alert_type,
        "risk": risk,
        "status": status,
        "action": action
    }

    EVENTS.append(event)

    if len(EVENTS) > MAX_EVENTS:
        EVENTS.pop(0)

    print(
        f"[ALERT] "
        f"{user} | {vehicle} | "
        f"{alert_type} | "
        f"RISK={risk} | "
        f"{status} | "
        f"{action}"
    )


# ============================================================
# Detection Logic
# ============================================================

def detect_unauthorized_access(user, vehicle):

    allowed = USER_VEHICLE_MAP.get(user, [])

    if vehicle not in allowed:

        failed_auth_tracker[user] += 1

        create_alert(
            user,
            vehicle,
            "UNAUTHORIZED_ACCESS",
            120
        )

        if failed_auth_tracker[user] >= 3:
            create_alert(
                user,
                vehicle,
                "REPEATED_AUTHORIZATION_FAILURES",
                180
            )

        return False

    return True


def detect_vehicle_enumeration(user):

    recent = list(vehicle_tracker[user])

    unique_vehicles = len(set(recent))

    if unique_vehicles >= 3:

        create_alert(
            user,
            recent[-1],
            "VEHICLE_ENUMERATION",
            150
        )


def detect_excessive_requests(user):

    now = time.time()

    recent_requests = [
        t for t in request_tracker[user]
        if now - t < 15
    ]

    if len(recent_requests) >= 8:

        create_alert(
            user,
            USER_VEHICLE_MAP[user][0],
            "EXCESSIVE_REQUEST_RATE",
            90
        )


# ============================================================
# Simulated Activity Generator
# ============================================================

def simulate_requests():

    while True:

        user = random.choice(USERS)

        # 75% normal behavior
        if random.random() < 0.75:

            vehicle = USER_VEHICLE_MAP[user][0]

        else:

            vehicle = random.choice(ALL_VEHICLES)

        request_tracker[user].append(time.time())
        vehicle_tracker[user].append(vehicle)

        authorized = detect_unauthorized_access(
            user,
            vehicle
        )

        detect_vehicle_enumeration(user)

        detect_excessive_requests(user)

        # occasional burst activity
        if random.random() < 0.15:

            for _ in range(random.randint(3, 6)):
                request_tracker[user].append(time.time())

        if authorized:
            print(
                f"[ACCESS] "
                f"{user} -> {vehicle} "
                f"(AUTHORIZED)"
            )

        time.sleep(random.uniform(0.8, 2.0))


# ============================================================
# Server Sent Events Stream
# ============================================================

@app.route("/api/events")
def stream():

    def event_stream():

        last_idx = 0

        while True:

            if len(EVENTS) > last_idx:

                for e in EVENTS[last_idx:]:

                    payload = "|".join([
                        e["timestamp"],
                        e["user"],
                        e["vehicle"],
                        e["alert_type"],
                        str(e["risk"]),
                        e["status"],
                        e["action"]
                    ])

                    yield f"data: {payload}\n\n"

                last_idx = len(EVENTS)

            time.sleep(0.5)

    return Response(
        event_stream(),
        mimetype="text/event-stream"
    )


# ============================================================
# Dashboard
# ============================================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">

<title>Phase 10 SOC Command Center</title>

<style>

body{
    background:#121212;
    color:#eeeeee;
    font-family:Arial, sans-serif;
    margin:20px;
}

h2{
    color:#00d4ff;
}

table{
    width:100%;
    border-collapse:collapse;
}

th,td{
    padding:10px;
    border-bottom:1px solid #333;
}

th{
    background:#1f1f1f;
}

tr:nth-child(even){
    background:#181818;
}

.low{
    color:#00ff88;
}

.medium{
    color:#ffeb3b;
}

.high{
    color:#ff9800;
}

.critical{
    color:#ff4444;
    font-weight:bold;
}

</style>
</head>

<body>

<h2>🚨 Phase 10 SOC Command Center</h2>

<table id="events">

<thead>
<tr>
<th>Timestamp</th>
<th>User</th>
<th>Vehicle</th>
<th>Alert Type</th>
<th>Risk</th>
<th>Status</th>
<th>Action</th>
</tr>
</thead>

<tbody></tbody>

</table>

<script>

const source = new EventSource("/api/events");

const tbody = document.querySelector("#events tbody");

source.onmessage = function(event){

    const fields = event.data.split("|");

    const row = document.createElement("tr");

    row.innerHTML = `
        <td>${fields[0]}</td>
        <td>${fields[1]}</td>
        <td>${fields[2]}</td>
        <td>${fields[3]}</td>
        <td>${fields[4]}</td>
        <td class="${fields[5].toLowerCase()}">${fields[5]}</td>
        <td>${fields[6]}</td>
    `;

    tbody.prepend(row);

    if(tbody.children.length > 50){
        tbody.removeChild(tbody.lastChild);
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
# Main
# ============================================================

if __name__ == "__main__":

    print("===================================")
    print("PHASE 10 DETECTION ENGINE ONLINE")
    print("Behavior-Based SOC Monitoring")
    print("===================================")

    threading.Thread(
        target=simulate_requests,
        daemon=True
    ).start()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )