from flask import Flask, render_template
from flask_socketio import SocketIO
from soc_pipeline import process_pipeline

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# -------------------------
# DASHBOARD ROUTE
# -------------------------
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


# -------------------------
# EMIT SOC EVENT
# -------------------------
def emit_soc_event(event):
    socketio.emit("soc_event", event)


# -------------------------
# STREAM SIMULATION (replace later with real ingestion)
# -------------------------
def stream_events():
    import time
    from soc_pipeline import fetch_logs

    while True:
        logs = fetch_logs()

        for log in logs:
            result = process_pipeline(log)

            socketio.emit("soc_event", {
                "timestamp": result["timestamp"],
                "user": result["identity"],
                "event_type": result["event_type"],
                "risk_score": result["risk_score"],
                "severity": result["severity"]
            })

        time.sleep(3)


# -------------------------
# BACKGROUND THREAD
# -------------------------
@socketio.on("connect")
def on_connect():
    print("Client connected")


# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    import threading

    thread = threading.Thread(target=stream_events)
    thread.daemon = True
    thread.start()

    socketio.run(app, host="0.0.0.0", port=5000, debug=True)