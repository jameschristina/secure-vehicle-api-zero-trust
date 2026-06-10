from flask import Flask, render_template, request, redirect, session, jsonify
from flask_socketio import SocketIO

from soc_pipeline import process_pipeline
from event_bus import EventBus
from soc_dashboard import ingest_pipeline_results

app = Flask(__name__)
app.secret_key = "dev-secret-key"

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

bus = EventBus()


# =========================================================
# AUTH
# =========================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        session["user"] = request.form.get("username", "analyst")
        return redirect("/dashboard")

    return render_template("login.html")


@app.route("/")
def root():
    return redirect("/login")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return render_template("dashboard.html")


# =========================================================
# HEALTH CHECK
# =========================================================
@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "events": bus.size()
    })


# =========================================================
# LOG STREAM
# =========================================================
@app.route("/logs")
def logs():
    return jsonify({
        "logs": bus.latest(100)
    })


# =========================================================
# VALIDATION (NORMALIZED SOC SCHEMA)
# =========================================================
def validate_event(event: dict) -> dict:
    return {
        "identity": event.get("user", "unknown"),
        "event_type": event.get("action", "unknown"),
        "vehicle_id": event.get("vehicle_id", "unknown"),
        "auth": bool(event.get("auth", False))
    }


# =========================================================
# INGEST PIPELINE
# =========================================================
@app.route("/ingest", methods=["POST"])
def ingest():
    raw_event = request.json or {}

    event = validate_event(raw_event)

    result = process_pipeline(event)

    normalized = {
        "identity": event["identity"],
        "event_type": event["event_type"],
        "vehicle_id": event["vehicle_id"],
        "risk_score": result.get("risk_score", 0),
        "severity": result.get("severity", "LOW"),
        "alert": result.get("alert", False),
        "technique": result.get("technique", "T0000"),
        "timestamp": result.get("timestamp")
    }

    # event bus
    bus.publish(normalized)

    # SOC dashboard ingestion (IMPORTANT FIX)
    ingest_pipeline_results(normalized)

    # realtime stream
   # REALTIME STREAM (ENHANCED SOC FORMAT)
    socketio.emit("soc_event", {
    "identity": normalized["identity"],
    "event_type": normalized["event_type"],
    "vehicle_id": normalized["vehicle_id"],
    "risk_score": normalized["risk_score"],
    "severity": normalized["severity"],
    "timestamp": normalized["timestamp"]
    })


# =========================================================
# SOCKET EVENTS
# =========================================================
@socketio.on("connect")
def on_connect():
    print("🔌 Client connected")


@socketio.on("disconnect")
def on_disconnect():
    print("❌ Client disconnected")


# =========================================================
# START SERVER
# =========================================================
if __name__ == "__main__":
    print("🚀 SOC COMMAND CENTER STARTING...")

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False
    )