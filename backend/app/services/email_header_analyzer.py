import re
from email.parser import Parser
from email.utils import parseaddr, parsedate_to_datetime

from app.utils import score_findings

RECEIVED_IP_RE = re.compile(
    r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b'
)

RECEIVED_TIMESTAMP_RE = re.compile(
    r'(?:;\s*)(\w{3},\s\d{1,2}\s\w{3}\s\d{4}\s\d{2}:\d{2}:\d{2}\s[+-]\d{4})'
)

RECEIVED_FROM_RE = re.compile(r'\bfrom\s+([^\s;(]+)', re.IGNORECASE)
RECEIVED_BY_RE = re.compile(r'\bby\s+([^\s;(]+)', re.IGNORECASE)
RECEIVED_WITH_RE = re.compile(r'\bwith\s+([^\s;(]+)', re.IGNORECASE)

ARC_SEAL_RE = re.compile(r'ARC-Seal', re.IGNORECASE)
ARC_MESSAGE_SIGNATURE_RE = re.compile(r'ARC-Message-Signature', re.IGNORECASE)

HEADER_FROM_NAME_RE = re.compile(r'^"?(.+?)"?\s*<', re.DOTALL)


def get_domain_from_email(value: str):
    if not value:
        return None

    _, email_address = parseaddr(value)

    if "@" not in email_address:
        return None

    return email_address.split("@", 1)[1].lower()


def get_display_name(value: str):
    if not value:
        return None
    name, _ = parseaddr(value)
    return name.strip() if name else None


def normalize_result(value: str):
    if not value:
        return "not_found"

    lowered = value.lower()

    if "pass" in lowered:
        return "pass"
    if "fail" in lowered:
        return "fail"
    if "softfail" in lowered:
        return "softfail"
    if "neutral" in lowered:
        return "neutral"
    if "none" in lowered:
        return "none"

    return "unknown"


def extract_auth_params(auth_header: str) -> dict:
    """Extract structured params from a single Authentication-Results header."""
    result = {}
    properties = re.findall(r'(\w+)=(\w+)', auth_header)
    for key, value in properties:
        result[key] = value
    return result


def extract_auth_results(headers):
    auth_headers = headers.get_all("Authentication-Results", [])
    combined = " ".join(auth_headers)

    spf_match = re.search(r'spf=(\w+)', combined, re.IGNORECASE)
    dkim_match = re.search(r'dkim=(\w+)', combined, re.IGNORECASE)
    dmarc_match = re.search(r'dmarc=(\w+)', combined, re.IGNORECASE)

    # Extract SPF domain if present
    spf_domain = None
    spf_mailfrom = re.search(r'smtp\.mailfrom=(?:[^\s;@]+@)?([a-zA-Z0-9.-]+)', combined, re.IGNORECASE)
    if spf_mailfrom:
        spf_domain = spf_mailfrom.group(1).lower()
    else:
        spf_of = re.search(r'domain of (?:[^\s;@]+@)?([a-zA-Z0-9.-]+)', combined, re.IGNORECASE)
        if spf_of:
            spf_domain = spf_of.group(1).lower()

    # Extract DKIM selector and domain if present
    dkim_selector = None
    dkim_domain = None
    for ah in auth_headers:
        if re.search(r'dkim=', ah, re.IGNORECASE):
            sel = re.search(r'\bs=([\w.-]+)', ah, re.IGNORECASE)
            if sel:
                dkim_selector = sel.group(1)
            dom = re.search(r'\bd=([\w.-]+)', ah, re.IGNORECASE)
            if dom:
                dkim_domain = dom.group(1).lower()
            else:
                dom_i = re.search(r'header\.i=@?([\w.-]+)', ah, re.IGNORECASE)
                if dom_i:
                    dkim_domain = dom_i.group(1).lower()

    # Extract DMARC policy from DMARC URI/rua if present
    dmarc_policy = None
    dmarc_pct = None
    dmarc_rua = None
    dmarc_uri_match = re.search(r'dmarc=(\w+)\s*.*?(?:p=(none|quarantine|reject))?', combined, re.IGNORECASE)
    if dmarc_uri_match:
        dmarc_policy = dmarc_uri_match.group(2)
    pct_match = re.search(r'pct=(\d+)', combined, re.IGNORECASE)
    if pct_match:
        dmarc_pct = int(pct_match.group(1))
    rua_match = re.search(r'rua=mailto:([^\s;]+)', combined, re.IGNORECASE)
    if rua_match:
        dmarc_rua = rua_match.group(1)

    return {
        "raw": auth_headers,
        "spf": normalize_result(spf_match.group(1)) if spf_match else "not_found",
        "dkim": normalize_result(dkim_match.group(1)) if dkim_match else "not_found",
        "dmarc": normalize_result(dmarc_match.group(1)) if dmarc_match else "not_found",
        "spf_domain": spf_domain,
        "dkim_selector": dkim_selector,
        "dkim_domain": dkim_domain,
        "dmarc_policy": dmarc_policy,
        "dmarc_pct": dmarc_pct,
        "dmarc_rua": dmarc_rua,
    }


def extract_arc_chain(headers):
    """Extract ARC (Authenticated Received Chain) seals and signatures."""
    seals = []
    arc_seals = headers.get_all("ARC-Seal", [])

    for i, seal in enumerate(arc_seals):
        seals.append({
            "instance": i + 1,
            "seal_raw": seal[:200] + "..." if len(seal) > 200 else seal,
        })

    return {
        "present": len(arc_seals) > 0,
        "seal_count": len(arc_seals),
        "seals": seals,
    }


def parse_received_timestamp(received: str):
    clean = re.sub(r'\s+', ' ', received).strip()
    if ';' in clean:
        cand = clean.rsplit(';', 1)[1].strip()
        cleaned_cand = re.sub(r'\s*\([^)]*\)\s*$', '', cand).strip()
        try:
            return cand, parsedate_to_datetime(cand)
        except Exception:
            try:
                return cleaned_cand, parsedate_to_datetime(cleaned_cand)
            except Exception:
                pass
    match = RECEIVED_TIMESTAMP_RE.search(received)
    if match:
        raw = match.group(1)
        try:
            return raw, parsedate_to_datetime(raw)
        except Exception:
            return raw, None
    return None, None


def format_delay(seconds: float) -> str:
    if seconds < 0:
        if seconds > -60:
            return "-<1m (skew)"
        return f"{int(seconds)}s (skew)"
    if seconds < 60:
        return f"+{int(seconds)}s"
    minutes = int(seconds // 60)
    rem_seconds = int(seconds % 60)
    if minutes < 60:
        return f"+{minutes}m {rem_seconds}s" if rem_seconds else f"+{minutes}m"
    hours = int(minutes // 60)
    rem_minutes = int(minutes % 60)
    if hours < 24:
        return f"+{hours}h {rem_minutes}m" if rem_minutes else f"+{hours}h"
    days = int(hours // 24)
    rem_hours = int(hours % 24)
    return f"+{days}d {rem_hours}h" if rem_hours else f"+{days}d"


def extract_received_chain(headers):
    received_headers = headers.get_all("Received", [])
    total_hops = len(received_headers)
    if total_hops == 0:
        return []

    # Parsed hop entries (index 0 is newest hop at recipient MX, index total_hops-1 is earliest at origin)
    parsed_items = []
    for index, received in enumerate(received_headers, start=1):
        clean_received = re.sub(r'\s+', ' ', received).strip()
        ips = RECEIVED_IP_RE.findall(clean_received)
        from_m = RECEIVED_FROM_RE.search(clean_received)
        by_m = RECEIVED_BY_RE.search(clean_received)
        with_m = RECEIVED_WITH_RE.search(clean_received)
        ts_str, dt = parse_received_timestamp(clean_received)

        parsed_items.append({
            "hop": index,
            "raw": clean_received[:300] + "..." if len(clean_received) > 300 else clean_received,
            "ips": sorted(set(ips)),
            "timestamp": ts_str,
            "dt": dt,
            "from_host": from_m.group(1) if from_m else None,
            "by_host": by_m.group(1) if by_m else None,
            "with_protocol": with_m.group(1) if with_m else None,
        })

    # Compute chronological transit delay:
    # Origin is parsed_items[-1] (chronological hop 1)
    # Next is parsed_items[-2] (chronological hop 2), ..., down to parsed_items[0] (chronological hop total_hops)
    for i in range(total_hops):
        # i is index in parsed_items (0 = recipient, total_hops-1 = origin)
        if i == total_hops - 1:
            # Earliest origin hop
            parsed_items[i]["delay_seconds"] = 0.0
            parsed_items[i]["delay_human"] = "+0s (Origin)"
            parsed_items[i]["delay_anomaly"] = False
            parsed_items[i]["clock_skew"] = False
        else:
            # Hop i happened AFTER hop i+1 chronologically
            curr_dt = parsed_items[i]["dt"]
            prev_dt = parsed_items[i + 1]["dt"]
            if curr_dt and prev_dt:
                try:
                    delta = (curr_dt - prev_dt).total_seconds()
                    parsed_items[i]["delay_seconds"] = round(delta, 1)
                    parsed_items[i]["delay_human"] = format_delay(delta)
                    parsed_items[i]["delay_anomaly"] = delta > 3600
                    parsed_items[i]["clock_skew"] = delta < -60
                except Exception:
                    parsed_items[i]["delay_seconds"] = None
                    parsed_items[i]["delay_human"] = "N/A"
                    parsed_items[i]["delay_anomaly"] = False
                    parsed_items[i]["clock_skew"] = False
            else:
                parsed_items[i]["delay_seconds"] = None
                parsed_items[i]["delay_human"] = "N/A"
                parsed_items[i]["delay_anomaly"] = False
                parsed_items[i]["clock_skew"] = False

    # Remove internal dt datetime object before returning dict
    for item in parsed_items:
        item.pop("dt", None)

    return parsed_items


def add_finding(findings, severity, title, detail, recommendation, mitre_id=None):
    finding = {
        "severity": severity,
        "title": title,
        "detail": detail,
        "recommendation": recommendation,
    }
    if mitre_id:
        finding["mitre_id"] = mitre_id
    findings.append(finding)


def analyze_email_headers(raw_headers: str):
    headers = Parser().parsestr(raw_headers)

    from_value = headers.get("From")
    reply_to = headers.get("Reply-To")
    return_path = headers.get("Return-Path")
    message_id = headers.get("Message-ID")
    subject = headers.get("Subject")
    date = headers.get("Date")
    user_agent = headers.get("User-Agent") or headers.get("X-Mailer")
    content_type = headers.get("Content-Type")
    content_language = headers.get("Content-Language")
    list_unsubscribe = headers.get("List-Unsubscribe")
    list_id = headers.get("List-ID")
    precedence = headers.get("Precedence")
    x_priority = headers.get("X-Priority")
    x_spam_score = headers.get("X-Spam-Score") or headers.get("X-Spam-Level")

    from_domain = get_domain_from_email(from_value)
    reply_to_domain = get_domain_from_email(reply_to)
    return_path_domain = get_domain_from_email(return_path)
    from_display_name = get_display_name(from_value)

    auth = extract_auth_results(headers)
    received_chain = extract_received_chain(headers)
    arc = extract_arc_chain(headers)

    findings = []

    if not from_value:
        add_finding(
            findings, "medium",
            "Missing From header",
            "The email does not contain a clear From header.",
            "Treat this as suspicious and verify the source manually."
        )

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        add_finding(
            findings, "medium",
            "Reply-To domain mismatch",
            f"From domain is {from_domain}, but Reply-To domain is {reply_to_domain}.",
            "Verify whether replies are being redirected to an unrelated domain."
        )

    if return_path_domain and from_domain and return_path_domain != from_domain:
        add_finding(
            findings, "low",
            "Return-Path domain differs from From domain",
            f"From domain is {from_domain}, but Return-Path domain is {return_path_domain}.",
            "Check whether this is expected for the sender's email infrastructure.",
            mitre_id="T1566.002"
        )

    if auth["spf"] in ("fail", "softfail"):
        add_finding(
            findings, "high",
            "SPF failed",
            f"SPF result is {auth['spf']}.",
            "Treat the sender as suspicious unless other trusted evidence confirms legitimacy.",
            mitre_id="T1566.002"
        )
    elif auth["spf"] == "not_found":
        add_finding(
            findings, "info",
            "SPF result not found",
            "No SPF result was found in Authentication-Results.",
            "Check full headers or validate sender domain DNS manually."
        )

    if auth["dkim"] == "fail":
        add_finding(
            findings, "high",
            "DKIM failed",
            "DKIM authentication failed.",
            "Treat the message as suspicious and inspect sender authenticity.",
            mitre_id="T1566.002"
        )
    elif auth["dkim"] == "not_found":
        add_finding(
            findings, "info",
            "DKIM result not found",
            "No DKIM result was found in Authentication-Results.",
            "Check whether the sender normally signs messages with DKIM."
        )

    if auth["dmarc"] == "fail":
        add_finding(
            findings, "high",
            "DMARC failed",
            "DMARC authentication failed.",
            "This is a strong phishing/spoofing indicator.",
            mitre_id="T1566.002"
        )
    elif auth["dmarc"] == "not_found":
        add_finding(
            findings, "info",
            "DMARC result not found",
            "No DMARC result was found in Authentication-Results.",
            "Check the sender domain's DMARC policy manually."
        )

    # Domain alignment calculations
    def check_domain_alignment(domain_a: str | None, domain_b: str | None) -> bool:
        if not domain_a or not domain_b:
            return False
        da = domain_a.lower().strip(".")
        db = domain_b.lower().strip(".")
        if da == db:
            return True
        return da.endswith("." + db) or db.endswith("." + da)

    spf_aligned = check_domain_alignment(from_domain, auth.get("spf_domain"))
    dkim_aligned = check_domain_alignment(from_domain, auth.get("dkim_domain"))
    dmarc_aligned = (auth["spf"] == "pass" and spf_aligned) or (auth["dkim"] == "pass" and dkim_aligned)

    auth["spf_aligned"] = spf_aligned
    auth["dkim_aligned"] = dkim_aligned
    auth["dmarc_aligned"] = dmarc_aligned

    # DMARC policy check
    if auth["dmarc_policy"] == "reject":
        add_finding(
            findings, "info",
            "DMARC reject policy detected",
            "Sender has DMARC reject policy — legitimate mail should pass authentication.",
            "If DMARC fails with reject policy, this is a near-certain spoof attempt."
        )

    # DKIM alignment check
    if auth["dkim"] == "pass" and auth.get("dkim_domain") and from_domain:
        if auth["dkim_domain"] != from_domain:
            add_finding(
                findings, "low",
                "DKIM domain mismatch",
                f"DKIM signed by {auth['dkim_domain']}, but From domain is {from_domain}.",
                "Verify whether DKIM signing domain is an authorized sender for this domain."
            )

    # DMARC alignment failure check (when SPF or DKIM passed, but domain didn't align with From)
    if from_domain and (auth["spf"] == "pass" or auth["dkim"] == "pass") and not dmarc_aligned:
        add_finding(
            findings, "high" if auth.get("dmarc_policy") in ("quarantine", "reject") else "medium",
            "DMARC alignment failure",
            f"From domain '{from_domain}' does not align with SPF domain '{auth.get('spf_domain') or 'N/A'}' or DKIM domain '{auth.get('dkim_domain') or 'N/A'}'.",
            "Even if SPF or DKIM passed for an upstream sender, DMARC alignment failed for the From address.",
            mitre_id="T1566.002"
        )

    if auth.get("dkim_selector"):
        add_finding(
            findings, "info",
            "DKIM selector detected",
            f"DKIM selector: {auth['dkim_selector']}",
            "Can be used to look up the public key in DNS for verification."
        )

    if not message_id:
        add_finding(
            findings, "low",
            "Missing Message-ID",
            "The email does not contain a Message-ID header.",
            "Some legitimate systems omit it, but missing Message-ID can be suspicious."
        )

    if not subject:
        add_finding(
            findings, "low",
            "Missing Subject header",
            "The email has no Subject header.",
            "Lack of subject can indicate automated or malicious mail."
        )

    if len(received_chain) == 0:
        add_finding(
            findings, "medium",
            "No Received headers found",
            "No mail routing chain was detected.",
            "Analyze the full raw email source if available."
        )

    # ARC analysis
    if arc["present"]:
        add_finding(
            findings, "info",
            "ARC chain present",
            f"Email has {arc['seal_count']} ARC seal(s) — indicates it was forwarded by an intermediate system.",
            "ARC helps preserve authentication results across forwarding. Check ARC seals for validity."
        )

    # Received chain analysis
    all_received_ips = []
    for hop in received_chain:
        all_received_ips.extend(hop["ips"])
    if len(all_received_ips) >= 3:
        add_finding(
            findings, "info",
            "Multi-hop routing detected",
            f"Email passed through {len(received_chain)} hop(s) with {len(set(all_received_ips))} unique IP(s).",
            "Review each hop for anomalies in routing path."
        )

    anomalous_hops = [h for h in received_chain if h.get("delay_anomaly")]
    if anomalous_hops:
        first_ano = anomalous_hops[0]
        add_finding(
            findings, "medium",
            "Abnormal MTA transit delay",
            f"Relay latency of {first_ano.get('delay_human')} detected at hop {first_ano.get('hop')}.",
            "Investigate whether the delay was caused by greylisting, MTA queuing, or intermediate inspection.",
        )

    # Spam score from upstream if present
    if x_spam_score:
        try:
            spam_val = float(x_spam_score)
            if spam_val > 5:
                add_finding(
                    findings, "medium",
                    "Elevated spam score from upstream",
                    f"Upstream spam filter scored this email at {spam_val}.",
                    "Correlate with other signals before making a final determination."
                )
        except (ValueError, TypeError):
            pass

    # Precedence/bulk detection
    if precedence and precedence.lower() == "bulk":
        add_finding(
            findings, "info",
            "Bulk/precedence marker detected",
            "Email is marked with Precedence: bulk — likely mailing list traffic.",
            "Bulk markers can reduce urgency but do not rule out phishing."
        )

    score = score_findings(findings)

    if score >= 80:
        rating = "Low Risk"
    elif score >= 55:
        rating = "Suspicious"
    else:
        rating = "High Risk"

    return {
        "summary": {"score": score, "rating": rating, "total_findings": len(findings)},
        "headers": {
            "from": from_value,
            "from_display_name": from_display_name,
            "reply_to": reply_to,
            "return_path": return_path,
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "user_agent": user_agent,
            "content_type": content_type,
            "content_language": content_language,
            "list_unsubscribe": list_unsubscribe,
            "list_id": list_id,
            "x_priority": x_priority,
            "x_spam_score": x_spam_score,
        },
        "domains": {
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
        },
        "authentication": auth,
        "received_chain": received_chain,
        "arc": arc,
        "findings": findings,
    }
