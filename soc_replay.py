import time
import random
import requests

EVENTS = [
    "BRUTE_FORCE",
    "AUTH_SPIKE",
    "DEVICE_CHANGE",
    "BASELINE_DEVIATION",
    "PRIVILEGE_ABUSE",
    "VEHICLE_COMMAND_ACCESS"
]

VEHICLES = ["CAR100", "CAR101", "CAR102", "CAR103", "CAR104"]

def generate_event():
    return {
        "user": "analyst",
        "action": random.choice(EVENTS),
        "vehicle_id": random.choice(VEHICLES),
        "auth": True
    }

while True:
    r = requests.post("http://localhost:5000/ingest", json=generate_event())
    print(r.json())
    time.sleep(0.5)
