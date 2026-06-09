from collections import deque
from threading import Lock

class EventBus:
    def __init__(self, maxlen=1000):
        self.events = deque(maxlen=maxlen)
        self.lock = Lock()

    def publish(self, event: dict):
        with self.lock:
            self.events.append(event)

    def latest(self, limit=100):
        with self.lock:
            return list(self.events)[-limit:]
