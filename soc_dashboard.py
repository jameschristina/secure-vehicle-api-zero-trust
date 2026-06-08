import json
from collections import defaultdict, Counter
from datetime import datetime

import matplotlib.pyplot as plt


# =========================================================
# STORAGE
# =========================================================
events = []


# =========================================================
# INGEST PIPELINE OUTPUT
# =========================================================
def ingest_pipeline_results(result: dict):
    """
    Accepts SOC pipeline output (single event result)
    """
    events.append(result)


# =========================================================
# METRICS ENGINE
# =========================================================
def compute_metrics():

    risk_timeline = []
    severity_count = Counter()
    event_types = Counter()
    technique_count = Counter()

    identity_risk = defaultdict(int)

    for e in events:

        risk = e.get("risk_score", 0)
        severity = e.get("severity", "LOW")
        event_type = e.get("event_type", "unknown")
        technique = e.get("technique")

        risk_timeline.append(risk)
        severity_count[severity] += 1
        event_types[event_type] += 1

        identity = e.get("identity", "unknown")
        identity_risk[identity] += risk

        if isinstance(technique, dict):
            for k in technique:
                technique_count[k] += technique[k]
        elif technique:
            technique_count[technique] += 1

    return {
        "risk_timeline": risk_timeline,
        "severity_count": severity_count,
        "event_types": event_types,
        "identity_risk": identity_risk,
        "technique_count": technique_count
    }


# =========================================================
# PLOTS
# =========================================================
def plot_risk_timeline(risk_timeline):

    plt.figure(figsize=(10, 4))
    plt.plot(risk_timeline, marker="o")
    plt.title("SOC Risk Score Timeline")
    plt.xlabel("Event Index")
    plt.ylabel("Risk Score")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("soc_risk_timeline.png")
    plt.close()


def plot_severity_distribution(severity_count):

    plt.figure(figsize=(6, 4))
    plt.bar(severity_count.keys(), severity_count.values())
    plt.title("Severity Distribution")
    plt.xlabel("Severity")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig("soc_severity_distribution.png")
    plt.close()


def plot_event_types(event_types):

    plt.figure(figsize=(8, 4))
    plt.bar(event_types.keys(), event_types.values())
    plt.title("Event Type Distribution")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("soc_event_types.png")
    plt.close()


def plot_identity_risk(identity_risk):

    plt.figure(figsize=(8, 4))
    plt.bar(identity_risk.keys(), identity_risk.values())
    plt.title("Identity Risk Scores")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("soc_identity_risk.png")
    plt.close()


def plot_mitre(technique_count):

    plt.figure(figsize=(8, 4))
    plt.bar(technique_count.keys(), technique_count.values())
    plt.title("MITRE ATT&CK Technique Frequency")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("soc_mitre.png")
    plt.close()


# =========================================================
# DASHBOARD EXPORT
# =========================================================
def export_dashboard():

    metrics = compute_metrics()

    plot_risk_timeline(metrics["risk_timeline"])
    plot_severity_distribution(metrics["severity_count"])
    plot_event_types(metrics["event_types"])
    plot_identity_risk(metrics["identity_risk"])
    plot_mitre(metrics["technique_count"])

    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_events": len(events),
        "summary": {
            "total_risk": sum(metrics["risk_timeline"]),
            "max_risk": max(metrics["risk_timeline"], default=0),
        }
    }

    with open("soc_dashboard_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("\n📊 SOC DASHBOARD GENERATED")
    print(" - soc_risk_timeline.png")
    print(" - soc_severity_distribution.png")
    print(" - soc_event_types.png")
    print(" - soc_identity_risk.png")
    print(" - soc_mitre.png")
    print(" - soc_dashboard_report.json")


# =========================================================
# SIMPLE RUNNER
# =========================================================
def run_dashboard(pipeline_results):

    for r in pipeline_results:
        ingest_pipeline_results(r)

    export_dashboard()


# =========================================================
# TEST ENTRYPOINT
# =========================================================
def test_main():
    sample = {
        "risk_score": 50,
        "severity": "HIGH",
        "event_type": "test",
        "identity": "user1",
        "technique": "T1078"
    }

    ingest_pipeline_results(sample)
    assert len(events) == 1
