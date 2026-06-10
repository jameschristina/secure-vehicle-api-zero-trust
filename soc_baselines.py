# soc_baselines.py
from collections import defaultdict

class VehicleBaseline:
    def __init__(self):
        self.event_counts = defaultdict(lambda: defaultdict(int))

    def update(self, event: dict):
        vehicle = event.get("vehicle_id")
        action = event.get("action")
        self.event_counts[vehicle][action] += 1

    def get_baseline(self, vehicle_id: str):
        return self.event_counts.get(vehicle_id, {})
