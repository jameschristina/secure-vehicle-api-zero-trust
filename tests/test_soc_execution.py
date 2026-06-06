import subprocess
import sys

PHASES = [
    "phase_01_vulnerable_api.py",
    "phase_02_authenticated_api.py",
    "phase_03_authorization_api.py",
    "phase_04_siem_detection.py",
    "phase_05_detection_engineering.py",
    "phase_06_threat_hunting.py",
    "phase_07_incident_response.py",
    "phase_08_threat_intelligence_correlations.py",
    "phase_09_soar_automation.py",
    "phase_10_detection_engine.py",
    "phase_11_ml_anomaly_detection.py",
    "phase_12_cloud_security.py",
    "phase_13_attack_path_analysis.py",
    "phase_14_attack_heatmap.py",
    "phase_15_executive_reporting.py",
    "phase_16_identity_federation.py",
    "phase_17_kubernetes_security.py",
    "phase_18_edr_simulation.py",
    "phase_19_purple_team.py",
    "phase_20_ai_soc_analyst.py",
]

def test_all_soc_phases_execute():
    for phase in PHASES:
        result = subprocess.run(
            [sys.executable, phase],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0, f"{phase} failed:\n{result.stderr}"
