# soc_mitre.py

MITRE_MAP = {
    "BRUTE_FORCE": "T1110",
    "AUTH_SPIKE": "T1078",
    "DEVICE_CHANGE": "T1098",
    "PRIVILEGE_ABUSE": "T1078.004",
    "VEHICLE_COMMAND_ACCESS": "T1040"
}

def tag_mitre(event):
    action = event.get("action", "UNKNOWN")
    return {
        "technique_id": MITRE_MAP.get(action, "T0000"),
        "technique_name": action
    }
