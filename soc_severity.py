# soc_severity.py

def escalate_severity(risk_score: int, burst: bool = False, baseline_anomaly: bool = False):
    score = risk_score

    if burst:
        score += 10

    if baseline_anomaly:
        score += 15

    if score < 10:
        return "LOW"
    elif score < 20:
        return "MEDIUM"
    elif score < 35:
        return "HIGH"
    else:
        return "CRITICAL"
