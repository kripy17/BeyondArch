import ipaddress
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from typing import Any

import dns.exception
import dns.resolver
import dns.reversename

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "DMARC"]
PUBLIC_FALLBACK_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]

def _system_nameservers() -> list[str]:
    try:
        resolver = dns.resolver.Resolver(configure=True)
        return [item for item in resolver.nameservers if item]
    except Exception:
        return []


def _resolver(use_public_fallback: bool = False) -> dns.resolver.Resolver:
    # Prefer the user's system resolver first. Corporate/campus networks often
    # block direct queries to 1.1.1.1/8.8.8.8, which made DNS look broken in the UI.
    resolver = dns.resolver.Resolver(configure=not use_public_fallback)
    if use_public_fallback:
        resolver.nameservers = PUBLIC_FALLBACK_NAMESERVERS
    resolver.timeout = 1.5
    resolver.lifetime = 3
    return resolver


def _answer_text(answer: Any) -> str:
    return answer.to_text().strip().strip('"')


def _resolve_with(resolver: dns.resolver.Resolver, domain: str, record_type: str) -> list[str]:
    answers = resolver.resolve(domain, record_type, lifetime=3, search=False)
    return [_answer_text(answer) for answer in answers]


def _resolve_record(domain: str, record_type: str) -> tuple[str, list[str], str | None]:
    errors = []
    for label, use_public in (("system", False), ("public-fallback", True)):
        try:
            return record_type, _resolve_with(_resolver(use_public), domain, record_type), None
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return record_type, [], None
        except dns.exception.Timeout:
            errors.append(f"{label} resolver timed out")
        except Exception as exc:  # Keep endpoint resilient across resolver/network quirks.
            errors.append(f"{label} resolver: {exc}")
    return record_type, [], "; ".join(errors) if errors else None


def _lookup_dmarc(domain: str) -> tuple[list[str], str | None]:
    """Query the DMARC policy record at _dmarc.<domain> (TXT)."""
    _, values, error = _resolve_record(f"_dmarc.{domain}", "TXT")
    policies = [v for v in values if v.lower().startswith("v=dmarc")]
    if not policies and not error:
        return [], None
    return policies, error


def _forward_confirm(resolver: dns.resolver.Resolver, pointer: str, ip: str) -> dict:
    """Forward-confirm a PTR result (FCrDNS): resolve A/AAAA and check the original IP."""
    forward: list[str] = []
    confirmed = False
    for rtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(pointer, rtype, lifetime=3, search=False)
        except Exception:
            continue
        for answer in answers:
            text = _answer_text(answer).rstrip(".")
            forward.append(text)
            if text == ip:
                confirmed = True
    return {"pointer": pointer, "forward": forward, "confirmed": confirmed}


def lookup_dns(domain: str) -> dict:
    """Resolve common DNS records for a domain without scraping or reputation lookup."""
    clean_domain = (domain or "").strip().rstrip(".").lower()
    system_resolvers = _system_nameservers()
    results: dict[str, Any] = {
        "target": clean_domain,
        "record_types": DNS_RECORD_TYPES,
        "records": {},
        "errors": {},
        "resolver": {
            "system_nameservers": system_resolvers,
            "public_fallback_nameservers": PUBLIC_FALLBACK_NAMESERVERS,
            "timeout_seconds": 3,
        },
    }

    if not clean_domain:
        results["errors"]["target"] = "No domain supplied."
        return results

    with ThreadPoolExecutor(max_workers=min(8, len(DNS_RECORD_TYPES))) as executor:
        futures = {executor.submit(_resolve_record, clean_domain, record_type): record_type for record_type in DNS_RECORD_TYPES}
        try:
            for future in as_completed(futures, timeout=8):
                record_type, records, error = future.result()
                results["records"][record_type] = records
                if error:
                    results["errors"][record_type] = error
        except TimeoutError:
            for future, record_type in futures.items():
                if not future.done():
                    results["errors"][record_type] = "DNS worker timed out."

    for record_type in DNS_RECORD_TYPES:
        results["records"].setdefault(record_type, [])

    # DMARC lives at _dmarc.<domain>, not at the apex — query it separately.
    dmarc_values, dmarc_error = _lookup_dmarc(clean_domain)
    results["records"]["DMARC"] = dmarc_values
    if dmarc_error:
        results["errors"]["DMARC"] = dmarc_error

    return results


def lookup_reverse_dns(ip: str) -> dict:
    """Resolve PTR/reverse DNS for an IP address."""
    clean_ip = (ip or "").strip()
    system_resolvers = _system_nameservers()
    results: dict[str, Any] = {
        "target": clean_ip,
        "record_types": ["PTR"],
        "records": {"PTR": []},
        "errors": {},
        "resolver": {
            "system_nameservers": system_resolvers,
            "public_fallback_nameservers": PUBLIC_FALLBACK_NAMESERVERS,
            "timeout_seconds": 3,
        },
    }

    try:
        ipaddress.ip_address(clean_ip)
    except ValueError:
        results["errors"]["target"] = "Not a valid IP address."
        return results

    reverse_name = dns.reversename.from_address(clean_ip)
    errors = []
    for label, use_public in (("system", False), ("public-fallback", True)):
        try:
            resolver = _resolver(use_public)
            answers = resolver.resolve(reverse_name, "PTR", lifetime=3, search=False)
            pointers = [_answer_text(answer).rstrip(".") for answer in answers]
            results["records"]["PTR"] = pointers
            results["errors"] = {}
            if pointers:
                # Forward-confirm the first PTR so a stale/spoofed pointer is visible.
                confirmation = _forward_confirm(resolver, pointers[0], clean_ip)
                results["fcrdns"] = {"performed": True, **confirmation}
            else:
                results["fcrdns"] = {"performed": False, "pointer": "", "forward": [], "confirmed": False}
            return results
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return results
        except dns.exception.Timeout:
            errors.append(f"{label} resolver timed out")
        except Exception as exc:
            errors.append(f"{label} resolver: {exc}")

    if errors:
        results["errors"]["PTR"] = "; ".join(errors)
    return results
