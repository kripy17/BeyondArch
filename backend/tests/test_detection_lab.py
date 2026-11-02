from fastapi.testclient import TestClient
from app.main import app
from app.services.mitre_navigator import generate_navigator_layer, parse_navigator_layer
from app.services.detection_simulator import simulate_detection

client = TestClient(app)


def test_generate_navigator_layer():
    techniques = [
        {"techniqueID": "T1059.001", "tactic": "Execution", "score": 100, "comment": "PowerShell coverage"},
        {"techniqueID": "T1566", "tactic": "Initial Access", "score": 50, "comment": "Phishing detection"},
    ]
    layer = generate_navigator_layer(name="Test Layer", techniques=techniques)

    assert layer["name"] == "Test Layer"
    assert layer["versions"]["navigator"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert len(layer["techniques"]) == 2
    assert layer["techniques"][0]["techniqueID"] == "T1059.001"
    assert layer["techniques"][0]["score"] == 100
    assert layer["techniques"][0]["color"] == "#22c55e"


def test_parse_navigator_layer():
    sample_layer = {
        "name": "Exported Layer",
        "domain": "enterprise-attack",
        "versions": {"navigator": "4.5"},
        "techniques": [
            {"techniqueID": "T1059.001", "score": 100, "tactic": "execution"},
            {"techniqueID": "T1110", "score": 40, "tactic": "credential-access"},
            {"techniqueID": "T1046", "score": 0, "tactic": "discovery"},
        ],
    }
    parsed = parse_navigator_layer(sample_layer)
    assert parsed["valid"] is True
    assert parsed["total_techniques"] == 3
    assert parsed["stats"]["full"] == 1
    assert parsed["stats"]["partial"] == 1
    assert parsed["stats"]["none"] == 1
    assert parsed["coverage_map"]["T1059.001"] == "full"
    assert parsed["coverage_map"]["T1110"] == "partial"
    assert parsed["coverage_map"]["T1046"] == "none"


def test_simulate_detection_sigma():
    sigma_rule = """title: Suspicious PowerShell EncodedCommand
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    - powershell.exe
    - -EncodedCommand
  condition: selection"""

    events = [
        {
            "id": "ev-1",
            "label": "Malicious Encoded Command",
            "expected": "match",
            "raw": "powershell.exe -NoP -EncodedCommand SQBFAFgA",
        },
        {
            "id": "ev-2",
            "label": "Benign Admin Backup",
            "expected": "benign",
            "raw": "powershell.exe -File C:\\admin\\backup.ps1",
        },
    ]

    res = simulate_detection(sigma_rule, "sigma", events)
    assert res["total_events"] == 2
    assert res["total_matches"] == 1
    assert res["true_positives"] == 1
    assert res["false_positives"] == 0
    assert res["results"][0]["verdict"] == "tp"
    assert res["results"][1]["verdict"] == "tn"


def test_simulate_detection_tuning_suggestion():
    # Rule that matches too broadly
    broad_rule = """title: Broad PowerShell Monitor
detection:
  selection:
    - powershell.exe
  condition: selection"""

    events = [
        {"id": "ev-1", "label": "Attack", "expected": "match", "raw": "powershell.exe -enc AAAA"},
        {"id": "ev-2", "label": "Benign Normal Helpdesk", "expected": "benign", "raw": "powershell.exe Get-Process"},
    ]

    res = simulate_detection(broad_rule, "sigma", events)
    assert res["false_positives"] == 1
    assert len(res["tuning_suggestions"]) >= 1


def test_api_detection_endpoints():
    # 1. Export Navigator layer
    export_resp = client.post(
        "/api/detection/mitre/navigator/export",
        json={
            "name": "SOC Layer",
            "techniques": [{"techniqueID": "T1059.001", "score": 100}],
        },
    )
    assert export_resp.status_code == 200
    layer_data = export_resp.json()
    assert layer_data["versions"]["navigator"] == "4.5"

    # 2. Import Navigator layer
    import_resp = client.post(
        "/api/detection/mitre/navigator/import",
        json={"layer": layer_data},
    )
    assert import_resp.status_code == 200
    parsed = import_resp.json()
    assert parsed["stats"]["full"] == 1

    # 3. Simulate rule
    sim_resp = client.post(
        "/api/detection/simulate",
        json={
            "rule_content": "CommandLine|contains: 'mimikatz'",
            "format": "sigma",
            "events": [{"label": "Mimikatz test", "expected": "match", "raw": "mimikatz.exe sekurlsa::logonpasswords"}],
        },
    )
    assert sim_resp.status_code == 200
    sim_data = sim_resp.json()
    assert sim_data["total_matches"] == 1
    assert sim_data["true_positives"] == 1
