import asyncio
import json

import httpx

RDAP_UA = "BeyondLabs/1.0"
RDAP_TIMEOUT_SECONDS = 10


async def _fetch_json(url: str) -> dict:
    async with httpx.AsyncClient(timeout=RDAP_TIMEOUT_SECONDS, follow_redirects=True) as client:
        response = await client.get(url, headers={"User-Agent": RDAP_UA, "Accept": "application/json"})
    response.raise_for_status()
    return response.json() or {}


def _vcard_values(entity: dict) -> list[list]:
    vcard_array = entity.get("vcardArray")
    if not isinstance(vcard_array, list) or len(vcard_array) < 2 or not isinstance(vcard_array[1], list):
        return []
    return [item for item in vcard_array[1] if isinstance(item, list)]


def _vcard_first(vcard_items: list[list], key: str) -> str:
    for item in vcard_items:
        if len(item) > 3 and item[0] == key:
            value = item[3]
            return str(value) if value else ""
    return ""


def _entity_with_role(entities: list, role: str) -> dict | None:
    for entity in entities:
        roles = entity.get("roles") or []
        if role in roles:
            return entity
    return None


def _rdap_events(data: dict) -> list[dict]:
    events = []
    for event in data.get("events") or []:
        action = str(event.get("eventAction", "")).strip()
        date = str(event.get("eventDate", "")).strip()
        if action and date:
            events.append({"action": action, "date": date})
    return events


def _parse_rdap_domain(data: dict, domain: str) -> dict:
    entities = data.get("entities") or []
    registrant = _entity_with_role(entities, "registrant")
    abuse = _entity_with_role(entities, "abuse")

    registrant_vcard = _vcard_values(registrant or {})
    abuse_vcard = _vcard_values(abuse or {})

    status = [str(item) for item in (data.get("status") or [])]
    nameservers = [
        str(ns.get("ldhName", "")).lower()
        for ns in (data.get("nameservers") or [])
        if isinstance(ns, dict) and ns.get("ldhName")
    ]

    registration_date = ""
    last_changed = ""
    for event in _rdap_events(data):
        if event["action"] == "registration" and not registration_date:
            registration_date = event["date"]
        if event["action"] == "last changed" and not last_changed:
            last_changed = event["date"]

    return {
        "domain": domain,
        "registrar": _vcard_first(_vcard_values(_entity_with_role(entities, "registrar") or {}), "fn"),
        "creation_date": registration_date,
        "expiry_date": next(
            (event["date"] for event in _rdap_events(data) if event["action"] == "expiration"),
            "",
        ),
        "name_servers": nameservers,
        "status": status,
        "organization": _vcard_first(registrant_vcard, "org") or _vcard_first(registrant_vcard, "fn"),
        "country": _vcard_first(registrant_vcard, "adr-country"),
        "abuse_contact": _vcard_first(abuse_vcard, "email"),
        "events": _rdap_events(data),
        "last_changed_date": last_changed,
        "raw": json.dumps(data, indent=2)[:16000],
    }


async def rdap_domain_lookup(domain: str) -> dict | None:
    """Query the RDAP bootstrap service for a domain's registration data."""
    if not domain:
        return None
    try:
        data = await _fetch_json(f"https://rdap.org/domain/{domain}")
    except Exception as exc:
        return {"domain": domain, "error": f"RDAP lookup failed ({type(exc).__name__})."}
    return _parse_rdap_domain(data, domain)


WHOIS_KEY_FIELDS = ("registrar", "creation_date", "expiry_date")


async def whois_lookup(domain: str) -> dict | None:
    """Run the system whois command for a domain, falling back to RDAP when unavailable."""
    if not domain:
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        output = stdout.decode("utf-8", errors="replace")[:16000]
        if proc.returncode != 0:
            result = {"domain": domain, "raw": "", "source": "whois", "error": stderr.decode("utf-8", errors="replace")[:500]}
        else:
            result = {
                "domain": domain,
                "raw": output,
                "source": "whois",
                "registrar": _extract_whois_field(output, "Registrar:"),
                "creation_date": _extract_whois_field(output, "Creation Date:"),
                "expiry_date": _extract_whois_field(output, "Registry Expiry Date:"),
                "name_servers": _extract_whois_list(output, "Name Server:"),
                "status": _extract_whois_list(output, "Domain Status:"),
                "organization": _extract_whois_field(output, "OrgName:") or _extract_whois_field(output, "Registrant Organization:"),
            }
    except (TimeoutError, FileNotFoundError, OSError):
        result = {"domain": domain, "raw": "", "source": "whois", "error": "whois command unavailable or timed out."}

    if result.get("error"):
        fallback = await rdap_domain_lookup(domain)
        if fallback and not fallback.get("error"):
            merged = {**result, **{key: fallback[key] for key in fallback if key not in {"domain", "raw", "error"}}}
            merged["source"] = "rdap.org fallback (system whois unavailable)"
            merged["fallback"] = True
            return merged

    if not any(result.get(field) for field in WHOIS_KEY_FIELDS) and not result.get("error"):
        fallback = await rdap_domain_lookup(domain)
        if fallback and not fallback.get("error"):
            for key, value in fallback.items():
                if key in {"domain", "raw"}:
                    continue
                if value and not result.get(key):
                    result[key] = value
            result["source"] = "whois + rdap.org enrichment (thin whois response)"
            result["fallback"] = True

    return result


async def rdap_lookup(ip: str) -> dict | None:
    """Query RDAP for an IP's allocation data."""
    if not ip:
        return None
    try:
        data = await _fetch_json(f"https://rdap.arin.net/registry/ip/{ip}")
    except Exception as exc:
        return {"ip": ip, "error": f"RDAP lookup failed ({type(exc).__name__})."}

    entities = data.get("entities", [])
    org = ""
    handle = data.get("handle", "")
    start_addr = data.get("startAddress", "")
    end_addr = data.get("endAddress", "")
    name = data.get("name", "")
    country = ""
    abuse_email = ""

    registrant = _entity_with_role(entities, "registrant")
    if registrant:
        registrant_vcard = _vcard_values(registrant)
        org = _vcard_first(registrant_vcard, "fn")
        country = _vcard_first(registrant_vcard, "adr-country")

    abuse = _entity_with_role(entities, "abuse")
    if abuse:
        abuse_email = _vcard_first(_vcard_values(abuse), "email")

    return {
        "ip": ip,
        "handle": handle,
        "range": f"{start_addr} - {end_addr}" if start_addr and end_addr else "",
        "name": name,
        "organization": org,
        "country": country,
        "abuse_contact": abuse_email,
        "events": _rdap_events(data),
        "raw": json.dumps(data, indent=2)[:16000],
    }


def _extract_whois_field(output: str, field: str) -> str:
    for line in output.splitlines():
        if line.strip().startswith(field):
            return line.split(field, 1)[-1].strip()
    return ""


def _extract_whois_list(output: str, field: str) -> list[str]:
    vals = []
    for line in output.splitlines():
        if line.strip().startswith(field):
            v = line.split(field, 1)[-1].strip()
            if v:
                vals.append(v)
    return vals
