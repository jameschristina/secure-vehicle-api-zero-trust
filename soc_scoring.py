def compute_severity(score: int) -> str:
    if score >= 150:
        return "CRITICAL"
    if score >= 100:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def normalize_score(score: int) -> int:
    """
    Ensures all phases stay within SOC-safe bounds
    """
    if score < 0:
        return 0
    if score > 200:
        return 200
    return score

