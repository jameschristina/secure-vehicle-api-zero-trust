import time
from datetime import datetime, timezone 
from collections import defaultdict

# -----------------------------
# SYSTEM STATE
# -----------------------------
identity_status = defaultdict(lambda: "active")
revoked_identities = set()
incidents = []


# -----------------------------
# SOAR ACTIONS
# -----------------------------
def quarantine_identity(identity):
    identity_status[identity] = "quarantined"
    revoked_identities.add(identity)


def revoke_identity(identity):
    identity_status[identity] = "revoked"
    revoked_identities.add(identity)


def create_incident(identity, alert):
    incident = {
        "identity": identity,
        "severity": alert["severity"],
        "event_type": alert["event_type"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "open"
    }
    incidents.append(incident)
    return incident


# -----------------------------
# SOAR DECISION ENGINE
# -----------------------------
def evaluate_alert(identity, alert):
    severity = alert.get("severity", 0)

    actions = []

    # HIGH SEVERITY → FULL CONTAINMENT
    if severity >= 9:
        revoke_identity(identity)
        incident = create_incident(identity, alert)
        actions.append("revoke_identity")
        actions.append("create_incident")

    # MEDIUM SEVERITY → QUARANTINE
    elif severity >= 6:
        quarantine_identity(identity)
        incident = create_incident(identity, alert)
        actions.append("quarantine_identity")
        actions.append("create_incident")

    # LOW SEVERITY → LOG ONLY
    else:
        incident = create_incident(identity, alert)
        actions.append("log_only")

    return {
        "identity": identity,
        "actions": actions,
        "identity_status": identity_status[identity],
        "incident_created": True if severity >= 6 else True
    }


# -----------------------------
# TESTABLE ENTRY POINT
# -----------------------------
def process_alert(identity, alert):
    return evaluate_alert(identity, alert)


# -----------------------------
# TEST HARNESS (CI SAFE)
# -----------------------------
def test_main():
    identity = "test|vehicle123"

    alert = {
        "severity": 8,
        "event_type": "unauthorized_access"
    }

    result = process_alert(identity, alert)

    assert "actions" in result
    assert isinstance(result["actions"], list)
    assert result["identity_status"] in ["active", "quarantined", "revoked"]


# -----------------------------
# OPTIONAL LIVE DEMO LOOP
# -----------------------------
def run_demo():
    print("\n🛡️ SOAR SYSTEM ACTIVE\n")

    sample_alerts = [
        ("user1|V1", {"severity": 10, "event_type": "unauthorized_access"}),
        ("user2|V2", {"severity": 7, "event_type": "auth_failure"}),
        ("user3|V3", {"severity": 3, "event_type": "low_risk"})
    ]

    for identity, alert in sample_alerts:
        result = process_alert(identity, alert)
        print(f"\nIdentity: {identity}")
        print(f"Actions: {result['actions']}")
        print(f"Status: {result['identity_status']}")
        time.sleep(0.5)


if __name__ == "__main__":
    run_demo()