# soc_burst.py
from collections import defaultdict, deque
import time

class BurstDetector:
    def __init__(self, window_seconds=10, threshold=3):
        self.window = window_seconds
        self.threshold = threshold
        self.events = defaultdict(deque)

    def check(self, event):
        key = (event["vehicle_id"], event["action"])
        now = time.time()

        q = self.events[key]
        q.append(now)

        # remove old events
        while q and now - q[0] > self.window:
            q.popleft()

        return len(q) >= self.threshold
