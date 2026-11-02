"""Shared outbound-request guard.

Every backend feature that connects to a user-supplied host must pass the
target through `assert_public_host` before opening a socket. The guard
resolves DNS and rejects loopback, private, link-local, and cloud-metadata
ranges unless the caller explicitly opted in (`allow_private=True` after an
authorization confirmation).

Known limitation (documented): this is a resolve-then-connect check. A
determined DNS-rebinding setup can still race past it; full mitigation
requires connection pinning.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class OutboundBlockedError(Exception):
    """Raised when a target fails the outbound guard."""

    def __init__(self, host: str, reason: str):
        self.host = host
        self.reason = reason
        super().__init__(f"Outbound request to '{host}' blocked: {reason}")


def host_of(target: str) -> str | None:
    """Extract a hostname from a raw host or http(s) URL."""
    value = (target or "").strip()
    if not value:
        return None
    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"}:
            return None
        return parsed.hostname
    if "/" in value or "@" in value:
        return None
    candidate = value.removesuffix(".")
    if ":" in candidate:
        # bare IPv6 literal (no port syntax supported on raw hosts)
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            return None
    return candidate or None


def _ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local address (cloud metadata range)"
    if ip.is_private:
        return "private/internal network address"
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "reserved/multicast/unspecified address"
    return None


def blocked_reason(target: str, *, allow_private: bool = False) -> str | None:
    """Return why the target may not be contacted, or None when allowed."""
    host = host_of(target)
    if not host:
        return "could not parse a clean hostname from the target"

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None

    if addr is not None:
        reason = _ip_blocked(addr)
        if reason and not allow_private:
            return reason
        return None

    if "." not in host:
        return "single-label hostname (no dot) — only fully qualified public domains are allowed"

    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        type_name = type(exc).__name__
        return f"DNS resolution failed ({type_name})"

    for info in infos:
        try:
            resolved = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        reason = _ip_blocked(resolved)
        if reason and not allow_private:
            return f"resolved to {resolved} — {reason}"

    return None


def assert_public_host(target: str, *, allow_private: bool = False) -> str:
    """Validate an outbound target; returns the cleaned hostname.

    Raises OutboundBlockedError with an honest, non-leaking reason.
    """
    host = host_of(target)
    reason = blocked_reason(target, allow_private=allow_private)
    if reason:
        raise OutboundBlockedError(host or (target or ""), reason)
    return host or (target or "")
