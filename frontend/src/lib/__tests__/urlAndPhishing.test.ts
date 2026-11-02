import { describe, it, expect } from 'vitest';
import {
  dissectUrl,
  decodePunycode,
  toUnicodeDomain,
  calculateShannonEntropy,
  refangUrl,
  defangUrl,
} from '../url/url-dissector';
import {
  parseEmailForensics,
  extractEmailAddress,
  checkDomainAlignment,
  formatDelay,
} from '../phishing/email-header-parser';

describe('URL Dissector & Forensics', () => {
  it('decodes Punycode strings accurately', () => {
    expect(decodePunycode('pple-43d')).toBe('аpple'); // Cyrillic 'а'
    expect(toUnicodeDomain('xn--pple-43d.com')).toBe('аpple.com');
  });

  it('calculates Shannon entropy correctly', () => {
    expect(calculateShannonEntropy('')).toBe(0);
    expect(calculateShannonEntropy('aaaaa')).toBe(0);
    // High randomness alphanumeric string
    const highEntropy = calculateShannonEntropy('8fB2xK9mP2qW7vR1tY5hJ8fL0cS4dG6e');
    expect(highEntropy).toBeGreaterThan(4.2);
  });

  it('refangs and defangs URLs properly', () => {
    const defanged = 'hxxps://evil[.]example[:]8080/path';
    expect(refangUrl(defanged)).toBe('https://evil.example:8080/path');
    expect(defangUrl('https://evil.example:8080/path')).toBe('hxxps://evil[.]example[:]8080/path');
  });

  it('dissects full URL anatomy including subdomains, query params, and entropy', () => {
    const raw = 'https://login.portal.target.com:8443/auth/session?token=abc12345&redirect=https://evil-c2.net#panel';
    const result = dissectUrl(raw);

    expect(result.scheme).toBe('https');
    expect(result.host).toBe('login.portal.target.com');
    expect(result.subdomain).toBe('login.portal');
    expect(result.subdomains).toEqual(['login', 'portal']);
    expect(result.apexDomain).toBe('target.com');
    expect(result.tld).toBe('com');
    expect(result.port).toBe(8443);
    expect(result.portCategory).toBe('common_alt');
    expect(result.path).toBe('/auth/session');
    expect(result.pathSegments).toEqual(['auth', 'session']);
    expect(result.queryParams).toHaveLength(2);
    expect(result.fragment).toBe('panel');
    expect(result.entropy.fullUrl).toBeGreaterThan(3);

    // Open redirect detection
    const redirectParam = result.queryParams.find((p) => p.key === 'redirect');
    expect(redirectParam?.isRedirectTarget).toBe(true);
    expect(result.redirectChain).toHaveLength(2);
    expect(result.redirectChain[1].host).toBe('evil-c2.net');
  });

  it('flags Punycode and Cyrillic homograph attacks', () => {
    const raw = 'https://xn--pple-43d.com/login';
    const result = dissectUrl(raw);

    expect(result.homograph.isPunycode).toBe(true);
    expect(result.homograph.unicodeString).toBe('аpple.com');
    expect(result.homograph.hasConfusables).toBe(true);
    expect(result.homograph.confusableChars[0].script).toBe('Cyrillic');
    expect(result.homograph.confusableChars[0].lookalikeLatin).toBe('a');
    expect(result.homograph.impersonatedBrand).toBe('apple');
    expect(result.signals.some((s) => s.id === 'punycode_homograph')).toBe(true);
    expect(result.verdict).toMatch(/malicious|suspicious/);
  });

  it('detects embedded credentials in URL', () => {
    const raw = 'https://admin:SuperSecretPass123@evil-c2.net:1337/payload';
    const result = dissectUrl(raw);

    expect(result.username).toBe('admin');
    expect(result.password).toBe('SuperSecretPass123');
    expect(result.port).toBe(1337);
    expect(result.portCategory).toBe('c2_suspicious');
    expect(result.signals.some((s) => s.id === 'embedded_credentials')).toBe(true);
    expect(result.signals.some((s) => s.id === 'c2_port')).toBe(true);
  });

  it('detects direct executable payload extensions', () => {
    const raw = 'https://downloads.bad-server.xyz/updates/setup.exe';
    const result = dissectUrl(raw);

    expect(result.signals.some((s) => s.id === 'executable_payload')).toBe(true);
    expect(result.signals.some((s) => s.id === 'suspicious_tld')).toBe(true);
  });

  it('detects brand impersonation mismatch on unrelated domain', () => {
    const raw = 'https://microsoft-login-verify.attacker-portal.top/auth';
    const result = dissectUrl(raw);

    expect(result.brandImpersonation.detectedBrand).toBe('microsoft');
    expect(result.brandImpersonation.mismatchReason).toContain('attacker-portal.top');
    expect(result.signals.some((s) => s.id === 'brand_impersonation')).toBe(true);
  });

  it('simulates redirect hop chain for URL shorteners', () => {
    const raw = 'https://bit.ly/3xK9pQz';
    const result = dissectUrl(raw);

    expect(result.signals.some((s) => s.id === 'url_shortener')).toBe(true);
    expect(result.redirectChain.length).toBeGreaterThanOrEqual(2);
    expect(result.redirectChain[0].hopType).toBe('shortener');
  });
});

describe('Email Header Parser & Phishing Forensics', () => {
  it('extracts email addresses and display names accurately', () => {
    const r1 = extractEmailAddress('John Doe <john.doe@enterprise.com>');
    expect(r1.displayName).toBe('John Doe');
    expect(r1.address).toBe('john.doe@enterprise.com');
    expect(r1.domain).toBe('enterprise.com');

    const r2 = extractEmailAddress('attacker@malicious.xyz');
    expect(r2.displayName).toBeNull();
    expect(r2.address).toBe('attacker@malicious.xyz');
    expect(r2.domain).toBe('malicious.xyz');
  });

  it('verifies relaxed domain alignment', () => {
    expect(checkDomainAlignment('paypal.com', 'paypal.com')).toBe(true);
    expect(checkDomainAlignment('mail.paypal.com', 'paypal.com')).toBe(true);
    expect(checkDomainAlignment('paypal.com', 'mail.paypal.com')).toBe(true);
    expect(checkDomainAlignment('paypal.com', 'evil-phish.com')).toBe(false);
  });

  it('formats transit delays cleanly', () => {
    expect(formatDelay(5)).toBe('+5s');
    expect(formatDelay(135)).toBe('+2m 15s');
    expect(formatDelay(3720)).toBe('+1h 2m');
    expect(formatDelay(90000)).toBe('+1d 1h');
    expect(formatDelay(-10)).toBe('-<1m (skew)');
  });

  it('performs full Authentication Quad-Check and identifies DMARC failure', () => {
    const headers = `
From: Microsoft Security <alert@microsoft-notifications.com>
To: victim@company.org
Subject: Urgent: Verify your Microsoft 365 account
Authentication-Results: mx.google.com;
  spf=pass smtp.mailfrom=marketing@bulk-mailer.net;
  dkim=pass d=bulk-mailer.net s=mail;
  dmarc=fail (p=reject) header.from=microsoft-notifications.com
Received: by mx.google.com; Wed, 11 May 2022 14:32:05 +0000
Received: by relay.bulk-mailer.net; Wed, 11 May 2022 14:32:00 +0000
    `.trim();

    const body = `
<p>Your account will be suspended within 24 hours.</p>
<p><a href="https://evil-c2.net/m365/login">https://account.microsoft.com/security</a></p>
    `.trim();

    const result = parseEmailForensics(headers, body);

    // Quad check
    expect(result.auth.spf.result).toBe('pass');
    expect(result.auth.spf.aligned).toBe(false); // bulk-mailer.net != microsoft-notifications.com
    expect(result.auth.dkim.result).toBe('pass');
    expect(result.auth.dkim.aligned).toBe(false);
    expect(result.auth.dmarc.aligned).toBe(false);
    expect(result.auth.dmarc.policy).toBe('reject');

    // MTA Hops
    expect(result.mtaHops).toHaveLength(2);
    expect(result.mtaHops[1].delayHuman).toBe('+0s (Origin)');
    expect(result.mtaHops[0].delayHuman).toBe('+5s');

    // Link Discrepancy
    expect(result.linkDiscrepancies).toHaveLength(1);
    const link = result.linkDiscrepancies[0];
    expect(link.status).toBe('DECEPTIVE MISMATCH');
    expect(link.anchorDomain).toBe('account.microsoft.com');
    expect(link.hrefDomain).toBe('evil-c2.net');

    // Urgency
    expect(result.urgency.score).toBeGreaterThan(0);
    expect(result.urgency.categories.some((c) => c.category === 'Urgency & Deadlines')).toBe(true);

    // Findings & Verdict
    expect(result.findings.some((f) => f.id === 'dmarc_alignment_failure')).toBe(true);
    expect(result.findings.some((f) => f.id === 'deceptive_hyperlink')).toBe(true);
    expect(result.verdict).toBe('malicious');
  });
});
