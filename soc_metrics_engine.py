import json
import glob
from datetime import datetime
from collections import Counter

EVENT_FILES = glob.glob("soc_events.json*")

def load_events():
    events = []
    for file in EVENT_FILES:
        try:
            if file.endswith(".json"):
                with open(file) as f:
                    data = json.load(f)
                    events.extend(data if isinstance(data, list) else [data])

            elif file.endswith(".jsonl"):
                with open(file) as f:
                    for line in f:
                        events.append(json.loads(line))
        except Exception:
            continue
    return events


events = load_events()

# -----------------------------
# CORE METRICS
# -----------------------------
total_events = len(events)
alerts = [e for e in events if e.get("type") == "alert"]
incidents = [e for e in events if e.get("type") == "incident"]

attack_vectors = Counter(e.get("attack_vector", "unknown") for e in events)
techniques = Counter(e.get("mitre", "T0000") for e in events)

# -----------------------------
# SOC HEALTH SCORE (REAL MODEL)
# -----------------------------
alert_ratio = len(alerts) / (total_events + 1)
incident_ratio = len(incidents) / (total_events + 1)

soc_health_score = round(
    (1 - alert_ratio * 0.5 - incident_ratio * 0.7) * 100,
    2
)

# -----------------------------
# EXECUTIVE REPORT
# -----------------------------
report = {
    "timestamp": datetime.utcnow().isoformat() + "Z",
    "total_events": total_events,
    "alerts": len(alerts),
    "incidents": len(incidents),

    "top_attack_vectors": attack_vectors.most_common(5),
    "top_mitre_techniques": techniques.most_common(5),

    "soc_health_score": soc_health_score,

    "risk_level": (
        "LOW" if soc_health_score > 80 else
        "MEDIUM" if soc_health_score > 50 else
        "HIGH"
    ),

    "recommendations": [
        "Increase identity-based anomaly detection coverage",
        "Improve Kubernetes runtime visibility",
        "Enhance EDR signal correlation",
        "Tune alert thresholds to reduce noise"
    ]
}

with open("soc_metrics.json", "w") as f:
    json.dump(report, f, indent=4)

print(json.dumps(report, indent=4))
