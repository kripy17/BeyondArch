import pytest
from app.services.email_header_analyzer import (
    analyze_email_headers,
    extract_auth_results,
    extract_received_chain,
    format_delay,
)
from app.services.safe_url_analyzer import analyze_static_url, safe_analyze_url


class TestEmailHeaderForensics:
    def test_format_delay_formatting(self):
        assert format_delay(15) == "+15s"
        assert format_delay(125) == "+2m 5s"
        assert format_delay(3660) == "+1h 1m"
        assert format_delay(90000) == "+1d 1h"
        assert "skew" in format_delay(-120)

    def test_received_chain_transit_delays(self):
        # Top header = newest (MX recipient), Bottom header = oldest (origin sender)
        raw_headers = (
            "Received: from mail-relay.target.com ([192.0.2.10]) by mx.google.com with ESMTPS id abc;\r\n"
            "        Wed, 11 May 2022 14:32:15 +0000\r\n"
            "Received: from outbound.attacker.com ([198.51.100.25]) by mail-relay.target.com with ESMTP id def;\r\n"
            "        Wed, 11 May 2022 14:32:05 +0000\r\n"
            "Received: from client-pc ([203.0.113.50]) by outbound.attacker.com with SMTP id ghi;\r\n"
            "        Wed, 11 May 2022 14:32:00 +0000\r\n"
            "From: spoofed@target.com\r\n"
            "To: victim@example.org\r\n"
            "Subject: Important Security Notice\r\n"
        )
        res = analyze_email_headers(raw_headers)
        chain = res["received_chain"]
        assert len(chain) == 3

        # Hop 3 is origin
        assert chain[2]["hop"] == 3
        assert chain[2]["delay_seconds"] == 0.0
        assert "Origin" in chain[2]["delay_human"]

        # Hop 2 took 5 seconds from Hop 3 (14:32:00 to 14:32:05)
        assert chain[1]["hop"] == 2
        assert chain[1]["delay_seconds"] == 5.0
        assert chain[1]["delay_human"] == "+5s"

        # Hop 1 took 10 seconds from Hop 2 (14:32:05 to 14:32:15)
        assert chain[0]["hop"] == 1
        assert chain[0]["delay_seconds"] == 10.0
        assert chain[0]["delay_human"] == "+10s"

    def test_abnormal_mta_transit_delay_flagged(self):
        # 2 hour delay between hops
        raw_headers = (
            "Received: by mx.google.com; Wed, 11 May 2022 16:32:00 +0000\r\n"
            "Received: by mail.sender.com; Wed, 11 May 2022 14:32:00 +0000\r\n"
            "From: billing@corp.com\r\n"
            "Subject: Delayed Invoice\r\n"
        )
        res = analyze_email_headers(raw_headers)
        findings = res["findings"]
        delay_findings = [f for f in findings if "Abnormal MTA transit delay" in f["title"]]
        assert len(delay_findings) == 1
        assert "2h" in delay_findings[0]["detail"]

    def test_dmarc_alignment_success(self):
        raw_headers = (
            "From: Support <support@paypal.com>\r\n"
            "Subject: Account Update\r\n"
            "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=support@paypal.com; dkim=pass d=paypal.com s=k1; dmarc=pass\r\n"
        )
        res = analyze_email_headers(raw_headers)
        auth = res["authentication"]
        assert auth["spf"] == "pass"
        assert auth["dkim"] == "pass"
        assert auth["spf_domain"] == "paypal.com"
        assert auth["dkim_domain"] == "paypal.com"
        assert auth["spf_aligned"] is True
        assert auth["dkim_aligned"] is True
        assert auth["dmarc_aligned"] is True

    def test_dmarc_alignment_failure_with_third_party_spf(self):
        # Common phishing scenario: attacker sends via Mailchimp/Sendgrid so SPF passes for sendgrid.net,
        # but From is executive@bank.com. DMARC fails because sendgrid.net does not align with bank.com!
        raw_headers = (
            "From: CEO <ceo@secure-bank.com>\r\n"
            "Subject: Wire Request\r\n"
            "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=bounces@sendgrid.net; dkim=pass d=sendgrid.net s=smtp; dmarc=fail (p=REJECT)\r\n"
        )
        res = analyze_email_headers(raw_headers)
        auth = res["authentication"]
        assert auth["spf"] == "pass"
        assert auth["spf_aligned"] is False
        assert auth["dkim_aligned"] is False
        assert auth["dmarc_aligned"] is False

        # Should produce a DMARC alignment failure finding
        findings = res["findings"]
        alignment_failures = [f for f in findings if "DMARC alignment failure" in f["title"]]
        assert len(alignment_failures) == 1
        assert "ceo@secure-bank.com" in res["headers"]["from"]


class TestUrlForensics:
    def test_punycode_and_homograph_detection(self):
        # Punycode impersonation: apple.com lookalike with Cyrillic 'а'
        url = "https://xn--pple-43d.com/login"
        res = analyze_static_url(url)
        signal_ids = [s["id"] for s in res["static_result"]["risk_signals"]]
        assert "punycode_host" in signal_ids
        assert res["risk_score"] > 0

    def test_embedded_credentials_detection(self):
        url = "https://admin:SuperSecretPass123@evil-c2.net:1337/payload"
        res = analyze_static_url(url)
        signal_ids = [s["id"] for s in res["static_result"]["risk_signals"]]
        assert "userinfo_at" in signal_ids
        assert "interesting_port" in signal_ids
        assert res["static_result"]["port"] == 1337

    def test_suspicious_extension_and_high_entropy(self):
        url = "https://cdn.malware-drop.com/updates/installer_a9B2c8D4e1F0g7H3k5L9mQ.exe?token=xK9mP2qW7vR1tY"
        res = analyze_static_url(url)
        signal_ids = [s["id"] for s in res["static_result"]["risk_signals"]]
        assert "suspicious_extension" in signal_ids
        assert ".exe" in res["static_result"]["suspicious_extensions"]

    def test_brand_impersonation_mismatch(self):
        url = "https://microsoft-security-verify.bad-domain.xyz/auth/login"
        res = analyze_static_url(url)
        signal_ids = [s["id"] for s in res["static_result"]["risk_signals"]]
        assert "brand_terms" in signal_ids
        assert "brand_impersonation_mismatch" in signal_ids
        assert res["verdict"] in ("suspicious", "needs_review")
