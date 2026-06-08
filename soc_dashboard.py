# soc_dashboard.py

from soc_metrics_engine import SOCMetricsEngine

engine = SOCMetricsEngine()

def render_dashboard():
    data = engine.snapshot()

    print("\n================ SOC DASHBOARD ================\n")

    print(f"Total Events: {data['metrics']['total_events']}")
    print(f"Alerts: {data['metrics']['alerts_generated']}")
    print(f"High Risk: {data['metrics']['high_risk_events']}")
    print(f"Medium Risk: {data['metrics']['medium_risk_events']}")
    print(f"Low Risk: {data['metrics']['low_risk_events']}")

    print("\nTop Identities:")
    for item in data["top_identities"]:
        print(f" - {item['identity']} | score={item['risk_score']}")

    print("\n=============================================\n")


def test_main():
    # lightweight CI hook
    render_dashboard()
