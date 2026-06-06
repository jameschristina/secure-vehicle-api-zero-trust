# soc_metrics.py

import json
import glob
from collections import Counter

# =========================
# CONFIGURATION
# =========================
EVENT_FILES = glob.glob("soc_events.json*")  # support json and jsonl
METRICS_OUTPUT = "soc_metrics.json"

# =========================
# HELPER FUNCTIONS
# =========================
def load_events(file_path):
    events = []
    if file_path.endswith(".json"):
        with open(file_path, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                events.extend(data)
            else:
                events.append(data)
    elif file_path.endswith(".jsonl"):
        with open(file_path, "r") as f:
            for line in f:
                events.append(json.loads(line))
    return events

# =========================
# AGGREGATE METRICS
# =========================
all_events = []
for file in EVENT_FILES:
    all_events.extend(load_events(file))

total_events = len(all_events)
alerts = [e for e in all_events if e.get("type") == "alert"]
incidents = [e for e in all_events if e.get("type") == "incident"]
attack_vectors = Counter(e.get("attack_vector") for e in all_events if e.get("attack_vector"))

# =========================
# COMPUTE METRICS
# =========================
metrics = {
    "total_events": total_events,
    "total_alerts": len(alerts),
    "total_incidents": len(incidents),
    "top_attack_vectors": attack_vectors.most_common(5),
}

# Optional: Compute a simple SOC health score
# (example: coverage ratio of incidents vs alerts)
metrics["soc_health_score"] = round(
    (len(alerts) + len(incidents)) / (total_events + 1) * 100, 2
)

# =========================
# OUTPUT TO FILE
# =========================
with open(METRICS_OUTPUT, "w") as f:
    json.dump(metrics, f, indent=4)

print(f"SOC Metrics generated: {METRICS_OUTPUT}")
print(json.dumps(metrics, indent=4))
