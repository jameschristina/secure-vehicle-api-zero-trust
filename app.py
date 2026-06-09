from flask import Flask, render_template, request, redirect, session, jsonify
from flask_socketio import SocketIO

from soc_pipeline import process_pipeline
from event_bus import EventBus

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
# HEALTH CHECK (IMPORTANT FOR DEBUGGING)
# =========================================================
@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "events": bus.size()
    })


# =========================================================
# LOG STREAM (EVENT BUS = SINGLE SOURCE OF TRUTH)
# =========================================================
@app.route("/logs")
def logs():
    return jsonify({
        "logs": bus.latest(100)
    })


# =========================================================
# INPUT VALIDATION (CRITICAL FIX)
# =========================================================
def validate_event(event: dict) -> dict:
    return {
        "user": event.get("user", "unknown"),
        "action": event.get("action", "unknown"),
        "vehicle_id": event.get("vehicle_id", "unknown"),
        "auth": bool(event.get("auth", False))
    }


# =========================================================
# INGEST PIPELINE ENTRYPOINT
# =========================================================
@app.route("/ingest", methods=["POST"])
def ingest():
    raw_event = request.json or {}

    event = validate_event(raw_event)

    result = process_pipeline(event)

    normalized = {
        "user": event["user"],
        "action": event["action"],
        "vehicle_id": event["vehicle_id"],
        "risk_score": result.get("risk_score", 0),
        "severity": result.get("severity", "LOW"),
        "alert": result.get("alert", False),
        "timestamp": result.get("timestamp")
    }

    # SINGLE SOURCE OF TRUTH
    bus.publish(normalized)

    # REALTIME STREAM
    socketio.emit("soc_event", normalized)

    return jsonify({
        "status": "ok",
        "event": normalized
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
# START SERVER (CLEAN ENTRYPOINT)
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