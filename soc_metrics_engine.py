from collections import defaultdict
from datetime import datetime

class SOCMetricsEngine:
    def __init__(self):
        self.reset()

    def reset(self):
        self.metrics = {
            "total_events": 0,
            "alerts_generated": 0,
            "high_risk_events": 0,
            "medium_risk_events": 0,
            "low_risk_events": 0,
        }

        self.by_identity = defaultdict(lambda: {
            "events": 0,
            "risk_score": 0,
            "alerts": 0,
        })

    def ingest_event(self, identity, event):
        self.metrics["total_events"] += 1

    def snapshot(self):
        return {
            "timestamp": datetime.now().isoformat(),
            "metrics": self.metrics,
            "top_identities": [],
        }


_metrics_engine = SOCMetricsEngine()


def get_metrics_engine():
    return _metrics_engine
