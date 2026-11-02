import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from app.utils import EMAIL_RE, IPV4_RE, URL_RE, unique_sorted, utc_now


def unique(items):
    return unique_sorted(items)

ISO_PREFIX_RE = re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(?P<body>.*)$')
SYSLOG_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$'
)
ISO_SYSLOG_RE = re.compile(
    r'^(?:(?P<source>\w+)\s+)?(?P<process>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$'
)
WEB_QUOTED_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+'
    r'(?:\[(?P<bracket_time>[^\]]+)\]\s+)?"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)
WINDOWS_EVENT_RE = re.compile(r'\b(?:EventID|Event\s+ID|event_id)[:= ]+(?P<event_id>\d{3,5})\b', re.IGNORECASE)
PROCESS_ARROW_RE = re.compile(r'(?P<parent>[\w.-]+\.exe)\s*(?:->|spawned|launched)\s*(?P<child>[\w.-]+\.exe)', re.IGNORECASE)
POWERSHELL_ENC_RE = re.compile(r'\b(?:EncodedCommand|-enc\b|-EncodedCommand\b)', re.IGNORECASE)
DOMAIN_RE = re.compile(r'(?<![@\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|edu|gov|in|dev|app|local)\b', re.IGNORECASE)

CEF_RE = re.compile(
    r'(?:^|.*?)\bCEF:\s*(?P<version>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<dev_version>[^|]*)\|(?P<event_class_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extension>.*)$',
    re.IGNORECASE
)

LEEF_RE = re.compile(
    r'(?:^|.*?)\bLEEF:\s*(?P<version>\d+(?:\.\d+)?)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<dev_version>[^|]*)\|(?P<event_class_id>[^|]*)\|(?:delimiter=(?P<delim>[^|]+)\|)?(?P<extension>.*)$',
    re.IGNORECASE
)

LOLBIN_PATTERNS = [
    (re.compile(r'\bcertutil(?:\.exe)?\s+.*(?:-urlcache|-split|-f|http)', re.I), "Certutil URL download cradle", "T1105 Ingress Tool Transfer"),
    (re.compile(r'\bmshta(?:\.exe)?\s+.*(?:http|javascript:|vbscript:)', re.I), "MSHTA arbitrary script execution", "T1218.005 Mshta"),
    (re.compile(r'\bwmic(?:\.exe)?\s+.*(?:process\s+call\s+create|/node:)', re.I), "WMIC process spawn or remote execution", "T1047 Windows Management Instrumentation"),
    (re.compile(r'\bregsvr32(?:\.exe)?\s+.*(?:\/s|\/u|\/i:)', re.I), "Regsvr32 Squiblydoo proxy execution", "T1218.010 Regsvr32"),
    (re.compile(r'\brundll32(?:\.exe)?\s+.*(?:javascript:|shell32\.dll|advpack\.dll|url\.dll)', re.I), "Rundll32 proxy execution", "T1218.011 Rundll32"),
    (re.compile(r'\bbitsadmin(?:\.exe)?\s+.*(?:\/transfer|\/create|\/addfile)', re.I), "Bitsadmin background job payload staging", "T1197 BITS Jobs"),
]

FAILED_LOGIN_WORDS = ["failed password", "authentication failure", "invalid user", "login failed", "failed login"]
SUCCESS_LOGIN_WORDS = ["accepted password", "session opened", "successful login", "login success"]
SCANNER_WORDS = ["sqlmap", "nikto", "nmap", "masscan", "zap", "acunetix", "gobuster", "ffuf", "dirbuster"]
WEB_PROBE_PATHS = ["/.env", "/wp-admin", "/backup", "/server-status", "/admin", "/login", "/.git", "/phpmyadmin"]
WEB_ATTACK_WORDS = ["../", "..%2f", "union select", "<script", "javascript:", "/etc/passwd", "cmd=", "xp_cmdshell"]
MALWARE_WORDS = ["mimikatz", "cobalt", "beacon", "meterpreter", "ransom", "keylogger"]
PRIORITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}






def parse_timestamp(value):
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except Exception:
        parsed = None
    if parsed is not None:
        if parsed.tzinfo is None:
            # Naive ISO strings carry no offset — treat them as UTC rather than
            # silently re-basing them onto the server's local timezone.
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S"):
        try:
            dt = datetime.strptime(text, fmt)
        except Exception:
            continue
        if fmt == "%b %d %H:%M:%S":
            # Syslog timestamps have no year. Assume the current year unless
            # that lands more than a day in the future (Dec 31 logs read in
            # early January belong to the previous year).
            now = datetime.now(timezone.utc)
            dt = dt.replace(year=now.year, tzinfo=timezone.utc)
            if (dt - now) > timedelta(days=1):
                dt = dt.replace(year=now.year - 1)
        elif dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return value


def time_bucket(timestamp, precision="minute"):
    parsed = parse_timestamp(timestamp)
    if not parsed or "T" not in parsed:
        return "unknown"
    if precision == "hour":
        return parsed[:13] + ":00Z"
    return parsed[:16] + ":00Z"


def severity_from_event(event):
    lower = f"{event.get('raw','')} {event.get('event_type','')} {event.get('message','')}".lower()
    if any(word in lower for word in ["critical", "ransom", "mimikatz", "meterpreter", "cobalt", "os credential", "event log was cleared", "log file was cleared", "eventid: 1102", "eventid: 104"]):
        return "critical"
    if any(word in lower for word in ["encodedcommand", "winword.exe -> powershell", "union select", "../", "..%2f", "/etc/passwd", "setcbprivilege", "sedebugprivilege"]):
        return "high"
    if event.get("event_type") in {"ssh_failed_login", "invalid_user_login", "web_probe", "scanner_activity", "powershell_suspicious", "edr_process_chain"}:
        return "medium"
    if event.get("event_type") in {"ssh_success_login", "http_request"}:
        return "info"
    return "info"


def headline_for(event):
    etype = event.get("event_type")
    if etype == "ssh_failed_login":
        return f"SSH failed login for {event.get('user') or 'unknown user'} from {event.get('source_ip') or 'unknown source'}"
    if etype == "invalid_user_login":
        return f"SSH invalid-user login attempt for {event.get('user') or 'unknown user'}"
    if etype == "ssh_success_login":
        return f"SSH successful login for {event.get('user') or 'unknown user'} from {event.get('source_ip') or 'unknown source'}"
    if etype == "web_probe":
        return f"Web probing request to {event.get('uri_path') or event.get('path') or 'unknown path'} returned {event.get('status_code') or event.get('status') or 'unknown'}"
    if etype == "http_request":
        return f"HTTP {event.get('method') or ''} {event.get('uri_path') or event.get('path') or ''} returned {event.get('status_code') or event.get('status') or 'unknown'}".strip()
    if etype == "powershell_suspicious":
        return "Suspicious PowerShell command indicator observed"
    if etype == "edr_process_chain":
        return f"Suspicious process chain {event.get('parent_process') or 'parent'} → {event.get('process_name') or 'child'}"
    if etype == "scanner_activity":
        return "Scanner/tool keyword observed in log event"
    if event.get("message"):
        return str(event["message"])[:180]
    return "Generic log event"


def why_for(event):
    etype = event.get("event_type")
    if etype in {"ssh_failed_login", "invalid_user_login"}:
        return "Failed SSH authentication can indicate password guessing, exposed service probing, misconfiguration, or a mistyped user account. Volume and source context decide priority."
    if etype == "ssh_success_login":
        return "A successful login is not inherently malicious, but it becomes important when it follows failures or originates from an unusual source."
    if etype == "web_probe":
        return "Requests for administrative, backup, or hidden paths are common reconnaissance signals. Response status helps determine exposure."
    if etype == "powershell_suspicious":
        return "Encoded PowerShell is often used by administrators and attackers. It requires host, parent process, and command context review."
    if etype == "edr_process_chain":
        return "Office or script interpreters spawning shells can be a strong initial-access or execution signal. Confirm parent/child process lineage."
    if etype == "scanner_activity":
        return "Known scanner/tool strings may indicate authorized testing or hostile reconnaissance. Check ownership and change windows."
    return "This event was normalized from the submitted dataset. Review surrounding events and extracted fields before disposition."


def next_check_for(event):
    etype = event.get("event_type")
    if etype in {"ssh_failed_login", "invalid_user_login"}:
        return "Check count by source IP, targeted users, successful logins after failures, geolocation/reputation if allowed, and whether the host should expose SSH."
    if etype == "ssh_success_login":
        return "Validate expected user, source IP, MFA/session logs, and whether failures from the same source occurred earlier."
    if etype in {"web_probe", "http_request"}:
        return "Review request path, status code, user-agent, response body size, and whether the source repeated similar paths."
    if etype in {"powershell_suspicious", "edr_process_chain"}:
        return "Correlate process tree, script block logs, command line, user session, parent document, and network connections."
    return "Correlate timestamp, host, user, source IP, and adjacent events in the same dataset."


def extract_processes(text):
    return unique(re.findall(r'\b[a-zA-Z0-9_.-]+\.exe\b', text))


def extract_domains(text, urls):
    domains = set()
    for url in urls:
        try:
            host = urlparse(url).hostname
            if host:
                domains.add(host.lower())
        except Exception:
            pass
    for match in DOMAIN_RE.findall(text):
        lower = match.lower()
        # Avoid classifying process names and HTTP version fragments as domains.
        if lower.endswith(".exe") or re.match(r'^\d+\.\d+(?:\.\d+)?$', lower):
            continue
        domains.add(lower)
    return sorted(domains)


def base_event(line, index):
    ips = IPV4_RE.findall(line)
    emails = EMAIL_RE.findall(line)
    urls = URL_RE.findall(line)
    domains = extract_domains(line, urls)
    processes = extract_processes(line)
    return {
        "id": f"event-{index}",
        "event_id": index,
        "index": "main",
        "source": "pasted_logs",
        "sourcetype": "generic_text",
        "category": "generic",
        "event_type": "generic",
        "severity": "info",
        "timestamp": None,
        "time_bucket": "unknown",
        "host": None,
        "user": None,
        "source_ip": ips[0] if ips else None,
        "src_ip": ips[0] if ips else None,
        "destination_ip": None,
        "dest_ip": None,
        "destination_port": None,
        "dest_port": None,
        "process_name": processes[-1] if processes else None,
        "parent_process": None,
        "command_line": None,
        "method": None,
        "uri_path": None,
        "path": None,
        "status_code": None,
        "status": None,
        "outcome": None,
        "action": None,
        "user_agent": None,
        "message": line,
        "headline": None,
        "why_it_matters": None,
        "next_check": None,
        "mitre_candidates": [],
        "raw": line,
        "iocs": {"ips": unique(ips), "emails": unique(emails), "urls": unique(urls), "domains": domains},
    }


def enrich_event(event):
    derived_sev = severity_from_event(event)
    existing_sev = event.get("severity")
    if existing_sev and existing_sev != "info" and PRIORITY_ORDER.get(existing_sev, 0) >= PRIORITY_ORDER.get(derived_sev, 0):
        event["severity"] = existing_sev
    else:
        event["severity"] = derived_sev
    event["headline"] = headline_for(event)

    event["why_it_matters"] = why_for(event)
    event["next_check"] = next_check_for(event)
    event["time_bucket"] = time_bucket(event.get("timestamp"))
    if event.get("event_type") in {"ssh_failed_login", "invalid_user_login", "ssh_success_login"}:
        event["mitre_candidates"] = ["T1110 Brute Force", "T1021.004 SSH"]
    elif event.get("event_type") in {"powershell_suspicious", "edr_process_chain"}:
        event["mitre_candidates"] = ["T1059.001 PowerShell", "T1204 User Execution"]
    elif event.get("event_type") in {"web_probe", "scanner_activity"}:
        event["mitre_candidates"] = ["T1595 Active Scanning", "T1592 Gather Victim Host Information"]
    return event


def parse_json_event(line, index):
    try:
        data = json.loads(line)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    event = base_event(line, index)
    msg = data.get("message") or data.get("msg") or data.get("event") or line
    event.update({
        "source": data.get("source") or data.get("index") or "json_upload",
        "sourcetype": data.get("sourcetype") or data.get("event.module") or data.get("log_type") or "json",
        "timestamp": parse_timestamp(data.get("timestamp") or data.get("@timestamp") or data.get("time")),
        "host": data.get("host") or data.get("hostname") or data.get("agent", {}).get("hostname") if isinstance(data.get("agent"), dict) else data.get("host"),
        "source_ip": data.get("src_ip") or data.get("source_ip") or data.get("client_ip") or event.get("source_ip"),
        "src_ip": data.get("src_ip") or data.get("source_ip") or data.get("client_ip") or event.get("source_ip"),
        "destination_ip": data.get("dest_ip") or data.get("destination_ip"),
        "dest_ip": data.get("dest_ip") or data.get("destination_ip"),
        "user": data.get("user") or data.get("username") or data.get("user.name"),
        "process_name": data.get("process_name") or data.get("process", {}).get("name") if isinstance(data.get("process"), dict) else data.get("process_name"),
        "command_line": data.get("command_line") or data.get("process", {}).get("command_line") if isinstance(data.get("process"), dict) else data.get("command_line"),
        "message": msg,
        "raw": line,
    })
    lower = line.lower()
    if any(word in lower for word in FAILED_LOGIN_WORDS):
        event.update({"event_type": "ssh_failed_login", "category": "authentication", "action": "login", "outcome": "failure", "status": "failed", "sourcetype": event.get("sourcetype") or "linux_auth"})
    elif POWERSHELL_ENC_RE.search(line):
        event.update({"event_type": "powershell_suspicious", "category": "endpoint", "action": "process_execution", "sourcetype": "powershell"})
    else:
        event["event_type"] = data.get("event_type") or data.get("event.action") or "json_event"
        event["category"] = data.get("category") or data.get("event.category") or "json"
    return enrich_event(event)


def parse_cef_extension(ext_str: str) -> dict:
    result = {}
    tokens = re.findall(r'(\w+)=((?:\\=|\\ |[^\s=])+)', ext_str)
    for k, v in tokens:
        result[k] = v.replace(r'\=', '=').replace(r'\ ', ' ')
    return result


def parse_cef_event(line: str, index: int):
    m = CEF_RE.search(line)
    if not m:
        return None
    data = m.groupdict()
    event = base_event(line, index)
    ext = parse_cef_extension(data.get("extension") or "")

    sev_raw = (data.get("severity") or "").strip().lower()
    if sev_raw.isdigit():
        num = int(sev_raw)
        sev = "critical" if num >= 9 else ("high" if num >= 7 else ("medium" if num >= 4 else "low"))
    elif any(w in sev_raw for w in ["crit", "fatal", "very-high"]):
        sev = "critical"
    elif "high" in sev_raw:
        sev = "high"
    elif "med" in sev_raw:
        sev = "medium"
    else:
        sev = "low"

    src_ip = ext.get("src") or ext.get("sourceAddress") or event.get("source_ip")
    dst_ip = ext.get("dst") or ext.get("destinationAddress") or event.get("destination_ip")
    user = ext.get("suser") or ext.get("sourceUserName") or ext.get("duser") or ext.get("destinationUserName")
    dpt = ext.get("dpt") or ext.get("destinationPort")
    spt = ext.get("spt") or ext.get("sourcePort")

    vendor = (data.get("vendor") or "cef").strip()
    product = (data.get("product") or "event").strip()

    event.update({
        "source": "cef",
        "sourcetype": f"{vendor}_{product}".lower().replace(" ", "_"),
        "category": "security",
        "event_type": data.get("event_class_id") or "cef_event",
        "severity": sev,
        "headline": data.get("name") or "CEF Event",
        "message": ext.get("msg") or data.get("name") or line,
        "source_ip": src_ip,
        "src_ip": src_ip,
        "destination_ip": dst_ip,
        "dest_ip": dst_ip,
        "user": user,
        "destination_port": int(dpt) if dpt and dpt.isdigit() else None,
        "dest_port": int(dpt) if dpt and dpt.isdigit() else None,
        "action": ext.get("act"),
        "uri_path": ext.get("request"),
    })
    return enrich_event(event)


def parse_leef_event(line: str, index: int):
    m = LEEF_RE.search(line)
    if not m:
        return None
    data = m.groupdict()
    event = base_event(line, index)
    ext_str = data.get("extension") or ""
    delim = data.get("delim") or "\t"
    pairs = ext_str.split(delim)
    ext = {}
    for p in pairs:
        if "=" in p:
            k, v = p.split("=", 1)
            ext[k.strip()] = v.strip()

    src_ip = ext.get("src") or ext.get("srcIP") or event.get("source_ip")
    dst_ip = ext.get("dst") or ext.get("dstIP") or event.get("destination_ip")
    user = ext.get("usrName") or ext.get("identSrc") or ext.get("accountName")
    vendor = (data.get("vendor") or "leef").strip()
    product = (data.get("product") or "event").strip()

    event.update({
        "source": "leef",
        "sourcetype": f"{vendor}_{product}".lower().replace(" ", "_"),
        "category": "security",
        "event_type": data.get("event_class_id") or "leef_event",
        "severity": "medium",
        "headline": f"LEEF {data.get('event_class_id') or 'event'}",
        "message": ext.get("msg") or line,
        "source_ip": src_ip,
        "src_ip": src_ip,
        "destination_ip": dst_ip,
        "dest_ip": dst_ip,
        "user": user,
    })
    return enrich_event(event)


def normalize_line(line: str, index: int) -> dict:
    original = line.rstrip("\n")
    json_event = parse_json_event(original, index)
    if json_event:
        return json_event

    cef_event = parse_cef_event(original, index)
    if cef_event:
        return cef_event

    leef_event = parse_leef_event(original, index)
    if leef_event:
        return leef_event


    event = base_event(original, index)
    working = original
    iso = ISO_PREFIX_RE.match(working)
    if iso:
        event["timestamp"] = parse_timestamp(iso.group("timestamp"))
        working = iso.group("body")

    web = WEB_QUOTED_RE.search(working)
    if web:
        data = web.groupdict()
        path = data.get("path")
        status_code = int(data.get("status")) if data.get("status") else None
        event.update({
            "source": "web",
            "sourcetype": "web_access",
            "category": "web",
            "event_type": "web_probe" if path and any(path.lower().startswith(p) for p in WEB_PROBE_PATHS) else "http_request",
            "timestamp": parse_timestamp(event.get("timestamp") or data.get("bracket_time")),
            "source_ip": data.get("ip"),
            "src_ip": data.get("ip"),
            "method": data.get("method"),
            "uri_path": path,
            "path": path,
            "status_code": status_code,
            "status": status_code,
            "action": "http_request",
            "outcome": "not_found" if status_code == 404 else ("success" if status_code and status_code < 400 else "error"),
            "user_agent": data.get("user_agent"),
            "message": f'{data.get("method")} {path} returned {status_code}',
        })
        return enrich_event(event)

    syslog = SYSLOG_RE.match(working)
    if syslog:
        data = syslog.groupdict()
        msg = data.get("message", "")
        event.update({
            "timestamp": parse_timestamp(event.get("timestamp") or f"{data.get('month')} {data.get('day')} {data.get('time')}"),
            "host": data.get("host"),
            "process_name": data.get("process"),
            "process": data.get("process"),
            "message": msg,
        })
        working_message = msg
    else:
        compact = ISO_SYSLOG_RE.match(working)
        if compact:
            data = compact.groupdict()
            event.update({
                "source": data.get("source") or event.get("source"),
                "process_name": data.get("process"),
                "process": data.get("process"),
                "message": data.get("message") or working,
            })
            working_message = data.get("message") or working
        else:
            working_message = working

    lower = original.lower()
    msg_lower = working_message.lower()

    invalid_user_match = re.search(r'invalid user\s+([A-Za-z0-9_.@-]+)', working_message, re.IGNORECASE)
    user_match = invalid_user_match or re.search(r'(?:for user|for|user)\s+([A-Za-z0-9_.@-]+)', working_message, re.IGNORECASE)
    if user_match:
        user = user_match.group(1)
        if user.lower() not in {"invalid", "user", "from"}:
            event["user"] = user

    port_match = re.search(r'\bport\s+(\d{1,5})\b', working_message, re.IGNORECASE)
    if port_match:
        event["destination_port"] = int(port_match.group(1))
        event["dest_port"] = int(port_match.group(1))

    process_chain = PROCESS_ARROW_RE.search(original)
    if process_chain:
        event.update({
            "source": "endpoint",
            "sourcetype": "edr_process",
            "category": "endpoint",
            "event_type": "edr_process_chain",
            "parent_process": process_chain.group("parent"),
            "process_name": process_chain.group("child"),
            "action": "process_spawn",
            "outcome": "observed",
        })
    elif POWERSHELL_ENC_RE.search(original) or "powershell" in lower:
        event.update({
            "source": "endpoint",
            "sourcetype": "powershell",
            "category": "endpoint",
            "event_type": "powershell_suspicious" if POWERSHELL_ENC_RE.search(original) else "powershell_activity",
            "process_name": "powershell.exe",
            "action": "process_execution",
            "outcome": "observed",
            "command_line": working_message,
        })
    elif any(word in msg_lower for word in FAILED_LOGIN_WORDS):
        event.update({
            "source": event.get("source") if event.get("source") != "pasted_logs" else "auth",
            "sourcetype": "linux_auth",
            "category": "authentication",
            "event_type": "invalid_user_login" if "invalid user" in msg_lower else "ssh_failed_login",
            "action": "login",
            "outcome": "failure",
            "status": "failed",
        })
    elif any(word in msg_lower for word in SUCCESS_LOGIN_WORDS):
        event.update({
            "source": event.get("source") if event.get("source") != "pasted_logs" else "auth",
            "sourcetype": "linux_auth",
            "category": "authentication",
            "event_type": "ssh_success_login",
            "action": "login",
            "outcome": "success",
            "status": "success",
        })
    elif any(word in lower for word in SCANNER_WORDS):
        event.update({"event_type": "scanner_activity", "category": "recon", "sourcetype": "scanner_indicator", "action": "tool_observed"})
    outbound_match = re.search(r'(?:outbound to|connect to)\s+(\d{1,3}(?:\.\d{1,3}){3})', original, re.IGNORECASE)
    if outbound_match:
        dest_ip = outbound_match.group(1)
        event["destination_ip"] = dest_ip
        event["dest_ip"] = dest_ip
        if event.get("source_ip") == dest_ip:
            event["source_ip"] = None
            event["src_ip"] = None

    if WINDOWS_EVENT_RE.search(original) or "logname:" in lower:
        event.update({"event_type": "windows_event", "category": "windows", "sourcetype": "windows_eventlog"})
        eid_m = WINDOWS_EVENT_RE.search(original)
        if eid_m:
            event["event_id_code"] = eid_m.group("event_id")
        acct_m = re.search(r'(?:AccountName|TargetUserName|Account Name|SubjectUser|User):\s*([A-Za-z0-9_.@-]+)', original, re.IGNORECASE)
        if acct_m:
            event["user"] = acct_m.group(1)
        src_m = re.search(r'(?:SourceIP|Source Address|ClientAddress|Source Network Address):\s*(?:::ffff:)?(\d{1,3}(?:\.\d{1,3}){3})', original, re.IGNORECASE)
        if src_m:
            event["source_ip"] = src_m.group(1)
            event["src_ip"] = src_m.group(1)

    if event.get("event_type") == "generic" and event.get("source_ip") and "GET " in original:
        event.update({"event_type": "http_request", "category": "web", "sourcetype": "web_access"})

    return enrich_event(event)



def add_detection(detections, rule_id, title, severity, detail, matched_events, evidence, recommendation, mitre=None, confidence="medium"):
    detections.append({
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "detail": detail,
        "matched_event_ids": [event.get("event_id") for event in matched_events],
        "matched_count": len(matched_events),
        "evidence": evidence,
        "recommendation": recommendation,
        "mitre_candidates": mitre or [],
        "confidence": confidence,
        "why_it_matters": detail,
        "next_check": recommendation,
        "generated_at": utc_now(),
    })


def detect_per_event(events):
    detections = []
    for event in events:
        lower = event.get("raw", "").lower()
        if event.get("event_type") in {"powershell_suspicious", "edr_process_chain"}:
            add_detection(
                detections,
                "ENDPOINT_SUSPICIOUS_EXECUTION",
                "Suspicious endpoint execution pattern",
                "high" if event.get("event_type") == "edr_process_chain" else "medium",
                "PowerShell encoding or a suspicious parent/child process chain was observed.",
                [event],
                {"host": event.get("host"), "user": event.get("user"), "process": event.get("process_name"), "raw": event.get("raw")},
                "Correlate process tree, user activity, script block logs, file origin, and outbound network connections.",
                ["T1059.001 PowerShell", "T1204 User Execution"],
                "high",
            )
        if event.get("event_type") == "web_probe" or any(path in lower for path in WEB_PROBE_PATHS):
            add_detection(
                detections,
                "WEB_SENSITIVE_PATH_PROBING",
                "Sensitive web path probing",
                "medium",
                "The request targeted administrative, backup, hidden, or commonly probed web paths.",
                [event],
                {"source_ip": event.get("source_ip"), "path": event.get("uri_path"), "status_code": event.get("status_code")},
                "Review whether the path exists, whether response status changed, and whether the source repeats probing behavior.",
                ["T1595 Active Scanning"],
                "medium",
            )
        if any(word in lower for word in WEB_ATTACK_WORDS):
            add_detection(
                detections,
                "WEB_ATTACK_PATTERN",
                "Web attack pattern detected",
                "high",
                "The log contains a common web attack or exploit-test pattern.",
                [event],
                {"source_ip": event.get("source_ip"), "path": event.get("uri_path"), "raw": event.get("raw")},
                "Review payload, response status, application logs, and whether exploitation succeeded.",
                ["T1190 Exploit Public-Facing Application"],
                "medium",
            )
        if any(word in lower for word in SCANNER_WORDS):
            add_detection(
                detections,
                "SCANNER_INDICATOR",
                "Scanner/tool indicator detected",
                "medium",
                "The event contains a known scanner/tool keyword. This can be authorized or hostile depending on scope.",
                [event],
                {"source_ip": event.get("source_ip"), "raw": event.get("raw")},
                "Confirm whether scanning was authorized and compare against approved testing windows.",
                ["T1595 Active Scanning"],
                "medium",
            )
        if any(word in lower for word in ["event log was cleared", "log file was cleared", "eventid: 1102", "eventid: 104", "wevtutil cl"]):
            add_detection(
                detections,
                "LOG_CLEARING_TAMPERING",
                "Event log clearing detected (defense evasion)",
                "critical",
                "Security or system audit logs were intentionally cleared or tampered with.",
                [event],
                {"host": event.get("host"), "user": event.get("user"), "raw": event.get("raw")},
                "Treat as high priority incident; check who had access, isolate host, and verify offline backups.",
                ["T1070.001 Clear Windows Event Logs"],
                "high",
            )
        if any(word in lower for word in ["setcbprivilege", "sedebugprivilege", "sebackupprivilege", "whoami /priv", "sudo:"]):
            add_detection(
                detections,
                "PRIVILEGE_TOKEN_ELEVATION",
                "Privileged token or privilege escalation activity",
                "high",
                "High-impact administrative privileges or privilege delegation were exercised.",
                [event],
                {"host": event.get("host"), "user": event.get("user"), "raw": event.get("raw")},
                "Verify whether elevation was authorized and inspect adjacent process executions.",
                ["T1078 Valid Accounts", "T1068 Exploitation for Privilege Escalation"],
                "high",
            )
        # Kerberoasting TGS request detection (EID 4769 with RC4 encryption 0x17)
        if (re.search(r'\b(?:4769|eventid:\s*4769)\b', lower) or "4769" in lower) and ("0x17" in lower or "rc4" in lower):
            add_detection(
                detections,
                "KERBEROASTING_TGS_REQUEST",
                "Kerberoasting attack pattern (RC4 service ticket request)",
                "high",
                "Kerberos Service Ticket (TGS) requested with weak RC4-HMAC encryption (0x17) for offline password hash cracking.",
                [event],
                {"host": event.get("host"), "user": event.get("user"), "raw": event.get("raw")},
                "Audit service accounts with SPNs, enforce AES-256 Kerberos encryption, and rotate service account passwords.",
                ["T1558.003 Kerberoasting", "T1078 Valid Accounts"],
                "high",
            )
        # Living-off-the-Land (LOLBIN) Execution Pattern Check
        for rx, desc, mitre_ttp in LOLBIN_PATTERNS:
            if rx.search(lower):
                add_detection(
                    detections,
                    "LOLBIN_EXECUTION_CHAIN",
                    f"Living-off-the-Land binary invocation ({desc})",
                    "high",
                    f"A native administrative utility was invoked with suspicious parameters ({desc}) commonly leveraged for stealth execution or payload ingress.",
                    [event],
                    {"raw": event.get("raw"), "process": event.get("process_name")},
                    "Inspect parent process lineage, network connections, and whether command was initiated by interactive administrative session.",
                    [mitre_ttp, "T1218 System Binary Proxy Execution"],
                    "high",
                )
                break
    return detections



def detect_correlations(events):
    detections = []
    failed_by_ip = defaultdict(list)
    success_by_ip = defaultdict(list)
    web_404_by_ip = defaultdict(list)
    web_probe_by_ip = defaultdict(list)
    outbound_by_dest = defaultdict(list)

    for event in events:
        ip = event.get("source_ip")
        if event.get("event_type") in {"ssh_failed_login", "invalid_user_login"} and ip:
            failed_by_ip[ip].append(event)
        if event.get("event_type") == "ssh_success_login" and ip:
            success_by_ip[ip].append(event)
        if event.get("sourcetype") == "web_access" and event.get("status_code") == 404 and ip:
            web_404_by_ip[ip].append(event)
        if event.get("event_type") == "web_probe" and ip:
            web_probe_by_ip[ip].append(event)
        
        # Outbound beacon tracking
        dest = event.get("dest_ip") or event.get("destination_ip")
        if not dest:
            # Check raw for external IP / HTTPS outbound
            m = re.search(r'(?:outbound to|connect to)\s+(\d{1,3}(?:\.\d{1,3}){3})', event.get("raw", ""), re.I)
            if m:
                dest = m.group(1)
        if dest and dest != event.get("source_ip"):
            outbound_by_dest[dest].append(event)

    for ip, rows in failed_by_ip.items():
        if len(rows) >= 3:
            add_detection(
                detections,
                "MULTIPLE_FAILED_LOGINS_IP",
                "Multiple failed SSH logins from one source",
                "high" if len(rows) >= 5 else "medium",
                f"{len(rows)} SSH failed-login events were observed from {ip}.",
                rows,
                {"source_ip": ip, "count": len(rows), "users": unique([row.get("user") for row in rows])},
                "Check if the source later succeeded, whether targeted accounts are valid, and whether the service should be Internet-facing.",
                ["T1110 Brute Force", "T1021.004 SSH"],
                "high",
            )
            # Password spraying check: >= 3 distinct users from same IP
            targeted_users = unique([row.get("user") for row in rows if row.get("user")])
            if len(targeted_users) >= 3:
                add_detection(
                    detections,
                    "PASSWORD_SPRAYING_PATTERN",
                    "Password spraying attack pattern detected",
                    "high",
                    f"{len(targeted_users)} distinct usernames were targeted in failed auth attempts from {ip}.",
                    rows,
                    {"source_ip": ip, "targeted_users": targeted_users, "count": len(rows)},
                    "Check active directory lockout policies and enforce multi-factor authentication across targeted accounts.",
                    ["T1110.003 Password Spraying"],
                    "high",
                )

        if rows and success_by_ip.get(ip):
            add_detection(
                detections,
                "SUCCESS_AFTER_FAILURE",
                "Successful login after failed attempts from same source",
                "high",
                f"A successful SSH login from {ip} occurred in the same dataset after failed attempts.",
                rows + success_by_ip[ip],
                {"source_ip": ip, "failed_count": len(rows), "success_count": len(success_by_ip[ip])},
                "Validate account owner, session timeline, MFA, command history, and whether the source IP is expected.",
                ["T1110 Brute Force", "T1078 Valid Accounts"],
                "medium",
            )

    for ip, rows in web_404_by_ip.items():
        if len(rows) >= 2:
            add_detection(
                detections,
                "REPEATED_WEB_404",
                "Repeated web 404 probing",
                "medium",
                f"{len(rows)} HTTP 404 responses were observed from {ip}.",
                rows,
                {"source_ip": ip, "paths": unique([row.get("uri_path") for row in rows])},
                "Review requested paths, user-agent, response sizes, and whether the activity is from an approved scanner.",
                ["T1595 Active Scanning"],
                "medium",
            )

    for ip, rows in web_probe_by_ip.items():
        if len(rows) >= 2:
            add_detection(
                detections,
                "MULTI_PATH_WEB_PROBING",
                "Multiple sensitive web paths from one source",
                "medium",
                f"{len(rows)} sensitive-path requests were observed from {ip}.",
                rows,
                {"source_ip": ip, "paths": unique([row.get("uri_path") for row in rows])},
                "Confirm whether this was authorized content discovery and whether any path returned 200/403.",
                ["T1595 Active Scanning"],
                "medium",
            )

    for dest, rows in outbound_by_dest.items():
        if len(rows) >= 3:
            add_detection(
                detections,
                "SUSPICIOUS_OUTBOUND_BEACON",
                "Repetitive outbound network connection (possible C2 beacon)",
                "high" if len(rows) >= 5 else "medium",
                f"{len(rows)} repetitive outbound connections observed to external destination {dest}.",
                rows,
                {"destination_ip": dest, "connection_count": len(rows)},
                "Investigate process initiating outbound connections, inspect SSL/TLS certificates, and block C2 IP if malicious.",
                ["T1071.001 Web Protocols", "T1572 Protocol Tunneling"],
                "medium",
            )

    # Advanced C2 Beaconing Jitter Analysis
    jitter_results = calculate_beacon_jitter(events)
    for dest, jdata in jitter_results.items():
        if jdata.get("is_beacon"):
            matched_events = [e for e in events if (e.get("destination_ip") == dest or e.get("dest_ip") == dest or dest in (e.get("raw") or ""))]
            add_detection(
                detections,
                "C2_BEACONING_CADENCE_DETECTED",
                f"Deterministic C2 beaconing cadence detected to {dest}",
                "critical" if jdata.get("count", 0) >= 6 else "high",
                f"Observed periodic connections to {dest} with mean interval {jdata['mean_interval_sec']}s and remarkably low jitter ({jdata['jitter_pct']}%). This low variance strongly indicates automated C2 agent beaconing.",
                matched_events,
                jdata,
                "Isolate originating host, extract memory dumps to identify injected C2 implants (Cobalt Strike, Sliver, Mythic), and block destination at perimeter firewall.",
                ["T1071.001 Web Protocols", "T1572 Protocol Tunneling", "T1048 Exfiltration Over Alternative Protocol"],
                jdata.get("confidence", "high"),
            )

    # Privilege Escalation Follow-Through Check
    priv_events = [
        e for e in events
        if any(w in (e.get("raw") or "").lower() for w in ["setcbprivilege", "sedebugprivilege", "sebackupprivilege", "eventid: 4672", "sudo:"])
    ]
    if priv_events:
        admin_actions = [
            e for e in events
            if any(w in (e.get("raw") or "").lower() for w in [
                "net localgroup administrators", "useradd", "adduser", "usermod",
                "schtasks", "reg add", "new-service", "sc create", "wmic process call create"
            ])
        ]
        if admin_actions:
            add_detection(
                detections,
                "PRIVILEGE_ESCALATION_FOLLOWTHROUGH",
                "Privilege token delegation followed by administrative execution",
                "critical",
                f"{len(priv_events)} privileged token delegation events were observed followed by administrative user manipulation or persistence installation.",
                priv_events + admin_actions,
                {"privileged_events": len(priv_events), "admin_actions": len(admin_actions)},
                "Immediately verify user authorization, isolate host from Domain Controller, and inspect recently created users/tasks.",
                ["T1078 Valid Accounts", "T1068 Exploitation for Privilege Escalation", "T1098 Account Manipulation"],
                "high",
            )

    # Defense Evasion / Audit Log Tampering Follow-Through
    log_clear_events = [
        e for e in events
        if any(w in (e.get("raw") or "").lower() for w in ["event log was cleared", "log file was cleared", "eventid: 1102", "eventid: 104", "wevtutil cl"])
    ]
    if log_clear_events:
        other_host_events = [e for e in events if e not in log_clear_events and e.get("severity") in ["high", "critical"]]
        if other_host_events:
            add_detection(
                detections,
                "DEFENSE_EVASION_AUDIT_TAMPERING",
                "Security audit log clearing alongside critical intrusion activity",
                "critical",
                "Security audit log clearing was observed in combination with high/critical severity intrusion indicators, indicating active anti-forensic defense evasion.",
                log_clear_events + other_host_events,
                {"cleared_events": len(log_clear_events), "concurrent_critical": len(other_host_events)},
                "Preserve hypervisor/disk snapshot immediately for out-of-band forensics before adversary overwrites unallocated clusters.",
                ["T1070.001 Clear Windows Event Logs", "T1562 Impair Defenses"],
                "high",
            )

    return detections


def calculate_beacon_jitter(events):
    """
    Analyzes inter-arrival time deltas for destination IPs/domains.
    Computes mean interval (seconds), standard deviation, and jitter % (std_dev / mean * 100).
    Returns a dict mapping destination -> jitter analysis dict.
    """
    dest_timestamps = defaultdict(list)
    for event in events:
        dest = event.get("destination_ip") or event.get("dest_ip")
        if not dest:
            m = re.search(r'(?:outbound to|connect to|destination:)\s+(\d{1,3}(?:\.\d{1,3}){3})', event.get("raw", ""), re.I)
            if m:
                dest = m.group(1)
        if not dest or dest == event.get("source_ip"):
            continue

        ts_str = event.get("timestamp")
        epoch = None
        if ts_str:
            try:
                clean_ts = str(ts_str).replace("Z", "+00:00")
                epoch = datetime.fromisoformat(clean_ts).timestamp()
            except Exception:
                pass
        if epoch is None and event.get("time_bucket") and event.get("time_bucket") != "unknown":
            try:
                clean_ts = str(event["time_bucket"]).replace("Z", "+00:00")
                epoch = datetime.fromisoformat(clean_ts).timestamp()
            except Exception:
                pass
        if epoch is None and event.get("raw"):
            m = re.search(r'\b(\d{1,2}):(\d{2}):(\d{2})\b', event["raw"])
            if m:
                epoch = int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))

        if epoch is not None:
            dest_timestamps[dest].append(epoch)

    results = {}
    for dest, epochs in dest_timestamps.items():
        if len(epochs) < 4:
            continue
        sorted_epochs = sorted(epochs)
        deltas = []
        for i in range(len(sorted_epochs) - 1):
            diff = sorted_epochs[i + 1] - sorted_epochs[i]
            if diff > 0:
                deltas.append(diff)

        if len(deltas) >= 3:
            mean_delta = sum(deltas) / len(deltas)
            if mean_delta >= 5:
                variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
                std_dev = variance ** 0.5
                jitter_pct = (std_dev / mean_delta) * 100
                results[dest] = {
                    "destination": dest,
                    "count": len(epochs),
                    "mean_interval_sec": round(mean_delta, 1),
                    "std_dev_sec": round(std_dev, 1),
                    "jitter_pct": round(jitter_pct, 1),
                    "is_beacon": jitter_pct <= 25.0,
                    "confidence": "high" if jitter_pct <= 15.0 else ("medium" if jitter_pct <= 25.0 else "low"),
                }
    return results


def field_counts(events, field):
    values = Counter(str(event.get(field)) for event in events if event.get(field) not in (None, "", []))
    return values.most_common(20)


def compute_field_analytics(events):
    field_analytics = {}
    total = len(events)
    fields_to_profile = [
        "source_ip", "destination_ip", "user", "host", "event_type",
        "sourcetype", "severity", "process_name", "uri_path", "status_code", "action", "outcome"
    ]
    for field in fields_to_profile:
        values = [str(e.get(field)) for e in events if e.get(field) not in (None, "", "-", "—", [])]
        populated = len(values)
        coverage_pct = round((populated / total) * 100, 1) if total else 0.0
        counts = Counter(values)
        distinct_count = len(counts)
        top_entries = []
        for val, cnt in counts.most_common(10):
            pct = round((cnt / populated) * 100, 1) if populated else 0.0
            top_entries.append({"value": val, "count": cnt, "percentage": pct})
        field_analytics[field] = {
            "field": field,
            "total_populated": populated,
            "coverage_pct": coverage_pct,
            "distinct_count": distinct_count,
            "top_values": top_entries,
        }
    return field_analytics


def build_metrics(events, detections):
    top_fields = {}
    for field in ["source_ip", "user", "host", "event_type", "sourcetype", "severity", "process_name", "uri_path", "status_code", "action", "outcome"]:
        top_fields[field] = field_counts(events, field)
    timeline = defaultdict(lambda: {"events": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    for event in events:
        key = event.get("time_bucket") or "unknown"
        sev = event.get("severity") or "info"
        timeline[key]["events"] += 1
        if sev in timeline[key]:
            timeline[key][sev] += 1
    return {
        "total_events": len(events),
        "total_detections": len(detections),
        "event_types": dict(Counter(event.get("event_type") for event in events)),
        "sourcetypes": dict(Counter(event.get("sourcetype") for event in events)),
        "severity": dict(Counter(event.get("severity") for event in events)),
        "top_source_ips": top_fields["source_ip"],
        "top_users": top_fields["user"],
        "top_hosts": top_fields["host"],
        "top_paths": top_fields["uri_path"],
        "top_fields": top_fields,
        "field_analytics": compute_field_analytics(events),
        "timeline": dict(sorted(timeline.items())),
    }



def analyze_logs_siem(text: str) -> dict:
    raw_blocks = re.split(r'\n\s*\n+', text.strip())
    if len(raw_blocks) > 1 and any("eventid:" in b.lower() or "logname:" in b.lower() for b in raw_blocks):
        lines = [b.strip() for b in raw_blocks if b.strip()]
    elif len(raw_blocks) == 1 and ("eventid:" in raw_blocks[0].lower() or "logname:" in raw_blocks[0].lower()) and "\n" in raw_blocks[0]:
        lines = [raw_blocks[0].strip()]
    else:
        lines = [line for line in text.splitlines() if line.strip()]
    events = [normalize_line(line, index + 1) for index, line in enumerate(lines[:10000])]

    detections = detect_per_event(events) + detect_correlations(events)
    detections = sorted(detections, key=lambda d: (PRIORITY_ORDER.get(d.get("severity", "info"), 0), d.get("matched_count", 0)), reverse=True)
    metrics = build_metrics(events, detections)

    all_ips, all_urls, all_emails, all_domains = [], [], [], []
    for event in events:
        iocs = event.get("iocs", {})
        all_ips.extend(iocs.get("ips", []))
        all_urls.extend(iocs.get("urls", []))
        all_emails.extend(iocs.get("emails", []))
        all_domains.extend(iocs.get("domains", []))

    confidence = "high" if events and any(event.get("timestamp") for event in events) else "medium"
    return {
        "summary": {
            "analyzed_at": utc_now(),
            "total_input_lines": len(lines),
            "events_normalized": len(events),
            "detections_generated": len(detections),
            "alerts_generated": len(detections),
            "confidence": confidence,
            "freshness": "user_supplied_log_batch",
            "note": "SIEM Workspace normalizes user-supplied logs and runs deterministic local detections. Validate conclusions with asset and environment context.",
        },
        "metrics": metrics,
        "detections": detections,
        "alerts": detections,
        "events": events[:2000],
        "extracted_iocs": {
            "ips": unique(all_ips),
            "urls": unique(all_urls),
            "emails": unique(all_emails),
            "domains": unique(all_domains),
        },
        "limitations": [
            "Local batch analysis only; no live SIEM, EDR, firewall, or cloud telemetry is queried.",
            "SPL support is intentionally a small safe subset for local filtering and summarization.",
            "Timestamp and field extraction depends on available log format and may require analyst validation.",
            "Detections are deterministic hints, not final incident conclusions.",
        ],
    }
