from dataclasses import dataclass, asdict
from typing import Dict, Any, List


# -----------------------------
# WEIGHTS (tunable like real SOC)
# -----------------------------
WEIGHTS = {
    "siem": 0.25,
    "detection": 0.25,
    "threat_hunt": 0.20,
    "intel": 0.15,
    "incident": 0.10,
    "soar": 0.05,
}


# -----------------------------
# NORMALIZATION (0–100 clamp)
# -----------------------------
def clamp(score: float, min_v=0, max_v=100):
    return max(min_v, min(max_v, score))


def normalize(value: float, max_expected: float = 100.0) -> float:
    if value is None:
        return 0.0
    return clamp((value / max_expected) * 100.0)


# -----------------------------
# SCORE OBJECT (EXPLAINABLE)
# -----------------------------
@dataclass
class SOCScore:
    total_score: float
    severity: str
    breakdown: Dict[str, float]
    signals: List[str]


def severity_from_score(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


# -----------------------------
# CORE SCORING ENGINE
# -----------------------------
def compute_soc_score(stage_outputs: Dict[str, Any]) -> SOCScore:

    breakdown = {}
    signals = []

    total = 0.0

    for stage, weight in WEIGHTS.items():

        raw = stage_outputs.get(stage)

        if raw is None:
            continue

        # Accept either dict or numeric
        if isinstance(raw, dict):
            score = raw.get("score", 0)
            signal = raw.get("signal")
        else:
            score = float(raw)
            signal = None

        normalized = normalize(score, 100)

        weighted = normalized * weight

        breakdown[stage] = weighted
        total += weighted

        if signal:
            signals.append(signal)

    total = clamp(total)

    return SOCScore(
        total_score=total,
        severity=severity_from_score(total),
        breakdown=breakdown,
        signals=signals
    )


# -----------------------------
# EXPORT SAFE FORMAT FOR PIPELINE
# -----------------------------
def build_score_result(stage_outputs: Dict[str, Any]) -> Dict[str, Any]:
    score = compute_soc_score(stage_outputs)

    return {
        "score": score.total_score,
        "severity": score.severity,
        "breakdown": score.breakdown,
        "signals": score.signals
    }
