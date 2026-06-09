from phase_08.phase_08_threat_intelligence_correlations import (
    correlate_iocs,
    fetch_logs,
    generate_report,
    KNOWN_BAD_IDENTITIES,
)

def main():
    logs = fetch_logs()
    findings = correlate_iocs(logs)
    generate_report(findings)

def test_main():
    """
    Safe SOC execution entrypoint.
    Must NOT depend on HTTP or external systems.
    """
    logs = [
        {
            "role": "developer",
            "vehicle_id": "V123",
            "reason": "test",
            "timestamp": "2025-01-01T00:00:00Z",
        }
    ]

    findings = correlate_iocs(logs)

    assert isinstance(findings, list)
    assert len(findings) >= 1

    print("safe execution ok")

if __name__ == "__main__":
    main()
