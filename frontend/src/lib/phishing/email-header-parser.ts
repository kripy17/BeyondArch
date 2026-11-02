// Pure TypeScript RFC 5322 Header Parser & Phishing Forensics Engine
// Inspired by PhishTool, Sublime Security, Inky, and Cisco Talos

export interface AuthStatus {
  result: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unknown';
  domain?: string;
  ip?: string;
  selector?: string;
  policy?: 'none' | 'quarantine' | 'reject';
  aligned: boolean;
  notes?: string;
}

export interface AuthQuadCheck {
  spf: AuthStatus;
  dkim: AuthStatus;
  dmarc: AuthStatus & { spfAligned: boolean; dkimAligned: boolean };
  arc: {
    present: boolean;
    sealCount: number;
    status: 'pass' | 'fail' | 'none';
  };
}

export interface MtaHop {
  hop: number;
  chronologicalIndex: number;
  raw: string;
  fromHost: string | null;
  byHost: string | null;
  withProtocol: string | null;
  ips: string[];
  timestamp: string | null;
  delaySeconds: number | null;
  delayHuman: string;
  delayAnomaly: boolean;
  clockSkew: boolean;
  isUntrustedRelay: boolean;
}

export interface LinkDiscrepancy {
  anchorText: string;
  href: string;
  status: 'DECEPTIVE MISMATCH' | 'SUBDOMAIN SPOOF' | 'OPEN REDIRECT' | 'MATCH';
  reason: string;
  anchorDomain: string | null;
  hrefDomain: string;
  riskSeverity: 'high' | 'medium' | 'low' | 'info';
}

export interface UrgencyCategory {
  category: string;
  terms: string[];
  severity: 'high' | 'medium' | 'low';
}

export interface PhishingFinding {
  id: string;
  severity: 'high' | 'medium' | 'low' | 'info';
  title: string;
  detail: string;
  recommendation: string;
  mitreId?: string;
}

export interface ParsedEmailForensics {
  headers: {
    from: string;
    fromDisplayName: string | null;
    fromAddress: string;
    replyTo: string | null;
    returnPath: string | null;
    to: string | null;
    subject: string | null;
    date: string | null;
    messageId: string | null;
    mailer: string | null;
  };
  domains: {
    fromDomain: string;
    replyToDomain: string | null;
    returnPathDomain: string | null;
    fromReplyToMatch: boolean;
    fromReturnPathMatch: boolean;
  };
  auth: AuthQuadCheck;
  mtaHops: MtaHop[];
  linkDiscrepancies: LinkDiscrepancy[];
  urgency: {
    score: number;
    level: 'critical' | 'elevated' | 'moderate' | 'low';
    categories: UrgencyCategory[];
  };
  findings: PhishingFinding[];
  riskScore: number;
  verdict: 'malicious' | 'suspicious' | 'needs_review' | 'low_risk';
}

// Helpers
export function extractEmailAddress(raw: string): { displayName: string | null; address: string; domain: string } {
  if (!raw) return { displayName: null, address: '', domain: '' };
  const trimmed = raw.trim();
  const angleMatch = trimmed.match(/^([^<]*)<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>/);
  if (angleMatch) {
    const rawName = angleMatch[1].trim().replace(/^"|"$/g, '').trim();
    const address = angleMatch[2].toLowerCase();
    const domain = address.split('@')[1] || '';
    return { displayName: rawName || null, address, domain };
  }
  const simpleMatch = trimmed.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  if (simpleMatch) {
    const address = simpleMatch[1].toLowerCase();
    const domain = address.split('@')[1] || '';
    return { displayName: null, address, domain };
  }
  return { displayName: null, address: trimmed, domain: '' };
}

export function checkDomainAlignment(domainA: string | null, domainB: string | null): boolean {
  if (!domainA || !domainB) return false;
  const da = domainA.toLowerCase().trim();
  const db = domainB.toLowerCase().trim();
  if (da === db) return true;
  return da.endsWith(`.${db}`) || db.endsWith(`.${da}`);
}

export function formatDelay(seconds: number): string {
  if (seconds < 0) {
    if (seconds > -60) return '-<1m (skew)';
    return `${Math.round(seconds)}s (skew)`;
  }
  if (seconds < 60) return `+${Math.round(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  const remSec = Math.round(seconds % 60);
  if (minutes < 60) return remSec > 0 ? `+${minutes}m ${remSec}s` : `+${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const remMin = Math.round(minutes % 60);
  if (hours < 24) return remMin > 0 ? `+${hours}h ${remMin}m` : `+${hours}h`;
  const days = Math.floor(hours / 24);
  const remHours = Math.round(hours % 24);
  return remHours > 0 ? `+${days}d ${remHours}h` : `+${days}d`;
}

// RFC 2822 / 5322 timestamp parser
export function parseRfcDate(dateStr: string): Date | null {
  if (!dateStr) return null;
  const clean = dateStr.replace(/\s*\([^)]*\)\s*$/, '').trim();
  const d = new Date(clean);
  return isNaN(d.getTime()) ? null : d;
}

// Urgency keywords dictionary
const URGENCY_PATTERNS = [
  {
    category: 'Urgency & Deadlines',
    severity: 'high' as const,
    terms: ['immediately', 'within 24 hours', 'urgent action', 'account suspended', 'access terminated', 'suspended within', 'final notice', 'action required'],
  },
  {
    category: 'Credential Harvester',
    severity: 'high' as const,
    terms: ['verify your password', 'confirm account', 'sign-in attempt', 'unauthorized access', 'reset credentials', 'mfa verification', 'update password', 'security alert'],
  },
  {
    category: 'Financial & Wire Fraud',
    severity: 'high' as const,
    terms: ['wire transfer', 'invoice overdue', 'payment pending', 'remittance', 'direct deposit', 'w-2', 'gift card', 'payroll update'],
  },
  {
    category: 'Document Bait',
    severity: 'medium' as const,
    terms: ['shared a document', 'view secure document', 'docusign envelope', 'encrypted message', 'review attachment', 'purchase order'],
  },
];

// Parser function
export function parseEmailForensics(rawHeaders: string, rawBody: string = ''): ParsedEmailForensics {
  const headerLines = rawHeaders.split(/\r?\n/);
  const headerMap: Record<string, string[]> = {};

  let currentHeaderKey = '';
  for (const line of headerLines) {
    if (/^\s+/.test(line) && currentHeaderKey) {
      const lastIndex = headerMap[currentHeaderKey].length - 1;
      headerMap[currentHeaderKey][lastIndex] += ` ${line.trim()}`;
    } else {
      const colonIndex = line.indexOf(':');
      if (colonIndex > 0) {
        currentHeaderKey = line.slice(0, colonIndex).trim().toLowerCase();
        const value = line.slice(colonIndex + 1).trim();
        if (!headerMap[currentHeaderKey]) {
          headerMap[currentHeaderKey] = [];
        }
        headerMap[currentHeaderKey].push(value);
      }
    }
  }

  const getFirst = (key: string): string => (headerMap[key.toLowerCase()]?.[0] || '').trim();
  const getAll = (key: string): string[] => headerMap[key.toLowerCase()] || [];

  const rawFrom = getFirst('from');
  const rawReplyTo = getFirst('reply-to');
  const rawReturnPath = getFirst('return-path');
  const rawTo = getFirst('to');
  const subject = getFirst('subject') || null;
  const dateStr = getFirst('date') || null;
  const messageId = getFirst('message-id') || null;
  const mailer = getFirst('user-agent') || getFirst('x-mailer') || null;

  const fromInfo = extractEmailAddress(rawFrom);
  const replyToInfo = extractEmailAddress(rawReplyTo);
  const returnPathInfo = extractEmailAddress(rawReturnPath);

  const fromDomain = fromInfo.domain;
  const replyToDomain = replyToInfo.domain || null;
  const returnPathDomain = returnPathInfo.domain || null;

  const fromReplyToMatch = !replyToDomain || replyToDomain === fromDomain;
  const fromReturnPathMatch = !returnPathDomain || returnPathDomain === fromDomain;

  // Authentication-Results Parsing
  const authHeaders = getAll('authentication-results');
  const combinedAuth = authHeaders.join(' ');

  // SPF
  let spfResult: AuthStatus['result'] = 'none';
  const spfMatch = combinedAuth.match(/spf=(\w+)/i);
  if (spfMatch) {
    const val = spfMatch[1].toLowerCase();
    if (['pass', 'fail', 'softfail', 'neutral'].includes(val)) {
      spfResult = val as AuthStatus['result'];
    }
  }
  let spfDomain: string | undefined = undefined;
  const spfMailFromMatch = combinedAuth.match(/smtp\.mailfrom=(?:[^\s;@]+@)?([a-zA-Z0-9.-]+)/i) || combinedAuth.match(/domain of (?:[^\s;@]+@)?([a-zA-Z0-9.-]+)/i);
  if (spfMailFromMatch) {
    spfDomain = spfMailFromMatch[1].toLowerCase();
  }
  const spfAligned = checkDomainAlignment(fromDomain, spfDomain || null);

  // DKIM
  let dkimResult: AuthStatus['result'] = 'none';
  const dkimMatch = combinedAuth.match(/dkim=(\w+)/i);
  if (dkimMatch) {
    const val = dkimMatch[1].toLowerCase();
    if (['pass', 'fail'].includes(val)) {
      dkimResult = val as AuthStatus['result'];
    }
  }
  let dkimDomain: string | undefined = undefined;
  let dkimSelector: string | undefined = undefined;
  const dkimDomMatch = combinedAuth.match(/\bd=([a-zA-Z0-9.-]+)/i) || combinedAuth.match(/header\.i=@?([a-zA-Z0-9.-]+)/i);
  if (dkimDomMatch) dkimDomain = dkimDomMatch[1].toLowerCase();
  const dkimSelMatch = combinedAuth.match(/\bs=([a-zA-Z0-9.-]+)/i);
  if (dkimSelMatch) dkimSelector = dkimSelMatch[1];
  const dkimAligned = checkDomainAlignment(fromDomain, dkimDomain || null);

  // DMARC
  let dmarcResult: AuthStatus['result'] = 'none';
  const dmarcMatch = combinedAuth.match(/dmarc=(\w+)/i);
  if (dmarcMatch) {
    const val = dmarcMatch[1].toLowerCase();
    if (['pass', 'fail'].includes(val)) {
      dmarcResult = val as AuthStatus['result'];
    }
  }
  let dmarcPolicy: AuthStatus['policy'] = undefined;
  const dmarcPolMatch = combinedAuth.match(/p=(none|quarantine|reject)/i);
  if (dmarcPolMatch) dmarcPolicy = dmarcPolMatch[1].toLowerCase() as AuthStatus['policy'];

  const dmarcAligned = (spfResult === 'pass' && spfAligned) || (dkimResult === 'pass' && dkimAligned);

  // ARC
  const arcSeals = getAll('arc-seal');
  const arcAuth = getAll('arc-authentication-results');
  const arcPresent = arcSeals.length > 0;
  let arcStatus: 'pass' | 'fail' | 'none' = 'none';
  if (arcPresent) {
    arcStatus = arcAuth.some((h) => /arc=pass/i.test(h)) || /pass/i.test(arcSeals.join(' ')) ? 'pass' : 'fail';
  }

  const authQuad: AuthQuadCheck = {
    spf: {
      result: spfResult,
      domain: spfDomain,
      aligned: spfAligned,
    },
    dkim: {
      result: dkimResult,
      domain: dkimDomain,
      selector: dkimSelector,
      aligned: dkimAligned,
    },
    dmarc: {
      result: dmarcResult !== 'none' ? dmarcResult : dmarcAligned ? 'pass' : 'fail',
      policy: dmarcPolicy,
      aligned: dmarcAligned,
      spfAligned,
      dkimAligned,
    },
    arc: {
      present: arcPresent,
      sealCount: arcSeals.length,
      status: arcStatus,
    },
  };

  // MTA Received Headers
  const receivedRaw = getAll('received');
  const totalHops = receivedRaw.length;
  const parsedHops: Array<{
    hop: number;
    raw: string;
    fromHost: string | null;
    byHost: string | null;
    withProtocol: string | null;
    ips: string[];
    timestamp: string | null;
    dateObj: Date | null;
  }> = [];

  for (let idx = 0; idx < totalHops; idx++) {
    const raw = receivedRaw[idx];
    const fromMatch = raw.match(/\bfrom\s+([^\s;(]+)/i);
    const byMatch = raw.match(/\bby\s+([^\s;(]+)/i);
    const withMatch = raw.match(/\bwith\s+([^\s;(]+)/i);
    const ips = Array.from(new Set(raw.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || []));

    let timestamp: string | null = null;
    let dateObj: Date | null = null;
    if (raw.includes(';')) {
      const cand = raw.slice(raw.lastIndexOf(';') + 1).trim();
      timestamp = cand;
      dateObj = parseRfcDate(cand);
    }

    parsedHops.push({
      hop: idx + 1, // 1 = top / recipient MX
      raw,
      fromHost: fromMatch ? fromMatch[1] : null,
      byHost: byMatch ? byMatch[1] : null,
      withProtocol: withMatch ? withMatch[1] : null,
      ips,
      timestamp,
      dateObj,
    });
  }

  // Compute MTA chronological transit delay
  const mtaHops: MtaHop[] = [];
  for (let idx = 0; idx < totalHops; idx++) {
    const item = parsedHops[idx];
    const chronologicalIndex = totalHops - idx; // 1 = origin, totalHops = recipient
    let delaySeconds: number | null = null;
    let delayHuman = 'N/A';
    let delayAnomaly = false;
    let clockSkew = false;

    if (idx === totalHops - 1) {
      // Origin hop
      delaySeconds = 0;
      delayHuman = '+0s (Origin)';
    } else {
      const currDate = item.dateObj;
      const prevDate = parsedHops[idx + 1]?.dateObj;
      if (currDate && prevDate) {
        const diffMs = currDate.getTime() - prevDate.getTime();
        delaySeconds = Math.round(diffMs / 1000);
        delayHuman = formatDelay(delaySeconds);
        delayAnomaly = delaySeconds > 3600;
        clockSkew = delaySeconds < -60;
      }
    }

    const isUntrustedRelay = item.fromHost ? /(evil|phish|dynamic|broadband|dsl|dialup|free|temp)/i.test(item.fromHost) : false;

    mtaHops.push({
      hop: item.hop,
      chronologicalIndex,
      raw: item.raw,
      fromHost: item.fromHost,
      byHost: item.byHost,
      withProtocol: item.withProtocol,
      ips: item.ips,
      timestamp: item.timestamp,
      delaySeconds,
      delayHuman,
      delayAnomaly,
      clockSkew,
      isUntrustedRelay,
    });
  }

  // Link Discrepancy Extractor
  const linkDiscrepancies: LinkDiscrepancy[] = [];
  if (rawBody) {
    // Regex scan for <a> tags
    const linkTagRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
    let match: RegExpExecArray | null;
    while ((match = linkTagRegex.exec(rawBody)) !== null) {
      const href = match[1].trim();
      const rawAnchor = match[2].replace(/<[^>]+>/g, '').trim();

      let hrefDomain = '';
      try {
        hrefDomain = new URL(href).hostname.toLowerCase();
      } catch {
        hrefDomain = href.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
      }

      let anchorDomain: string | null = null;
      if (/^https?:\/\//i.test(rawAnchor) || /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(rawAnchor)) {
        try {
          anchorDomain = new URL(rawAnchor.includes('://') ? rawAnchor : `https://${rawAnchor}`).hostname.toLowerCase();
        } catch {
          anchorDomain = rawAnchor.split('/')[0].toLowerCase();
        }
      }

      if (anchorDomain && anchorDomain !== hrefDomain) {
        // High severity mismatch!
        linkDiscrepancies.push({
          anchorText: rawAnchor,
          href,
          status: 'DECEPTIVE MISMATCH',
          reason: `Display text points to '${anchorDomain}', but actual destination href goes to '${hrefDomain}'.`,
          anchorDomain,
          hrefDomain,
          riskSeverity: 'high',
        });
      } else if (hrefDomain && fromDomain && hrefDomain !== fromDomain && !hrefDomain.includes(fromDomain)) {
        linkDiscrepancies.push({
          anchorText: rawAnchor || href,
          href,
          status: 'OPEN REDIRECT',
          reason: `Link directs user away from sender domain '${fromDomain}' to external target '${hrefDomain}'.`,
          anchorDomain,
          hrefDomain,
          riskSeverity: 'medium',
        });
      } else {
        linkDiscrepancies.push({
          anchorText: rawAnchor || href,
          href,
          status: 'MATCH',
          reason: `Anchor text and destination href align cleanly with '${hrefDomain}'.`,
          anchorDomain,
          hrefDomain,
          riskSeverity: 'low',
        });
      }
    }
  }

  // Urgency & Lure Scorer
  const combinedText = `${subject || ''} ${rawBody || ''}`.toLowerCase();
  const detectedCategories: UrgencyCategory[] = [];
  let urgencyRawScore = 0;

  for (const cat of URGENCY_PATTERNS) {
    const matched = cat.terms.filter((term) => combinedText.includes(term));
    if (matched.length > 0) {
      detectedCategories.push({
        category: cat.category,
        terms: matched,
        severity: cat.severity,
      });
      urgencyRawScore += matched.length * (cat.severity === 'high' ? 25 : 15);
    }
  }

  const urgencyScore = Math.min(100, urgencyRawScore);
  let urgencyLevel: ParsedEmailForensics['urgency']['level'] = 'low';
  if (urgencyScore >= 60) urgencyLevel = 'critical';
  else if (urgencyScore >= 40) urgencyLevel = 'elevated';
  else if (urgencyScore >= 20) urgencyLevel = 'moderate';

  // Findings Synthesis
  const findings: PhishingFinding[] = [];

  // 1. From Display Name Spoofing
  if (fromInfo.displayName) {
    const displayLower = fromInfo.displayName.toLowerCase();
    const brandSpoof = ['microsoft', 'paypal', 'apple', 'google', 'chase', 'security team', 'admin'].find((b) => displayLower.includes(b));
    if (brandSpoof && !fromDomain.includes(brandSpoof)) {
      findings.push({
        id: 'display_name_spoof',
        severity: 'high',
        title: 'Display Name Brand Impersonation',
        detail: `Display name claims to be '${fromInfo.displayName}', but the underlying sender address is '${fromInfo.address}'.`,
        recommendation: 'Block sender address and flag display name spoofing in mail filter.',
        mitreId: 'T1566.002',
      });
    }
  }

  // 2. DMARC / Alignment
  if (!dmarcAligned) {
    findings.push({
      id: 'dmarc_alignment_failure',
      severity: dmarcPolicy === 'reject' ? 'high' : 'medium',
      title: 'DMARC Domain Alignment Failure',
      detail: `From domain '${fromDomain}' does not align with SPF sender ('${spfDomain || 'N/A'}') or DKIM domain ('${dkimDomain || 'N/A'}').`,
      recommendation: 'Reject or quarantine email according to organizational DMARC enforcement policy.',
      mitreId: 'T1566.002',
    });
  }

  if (spfResult === 'fail' || spfResult === 'softfail') {
    findings.push({
      id: 'spf_failure',
      severity: 'high',
      title: 'SPF Authentication Failed',
      detail: `Sender IP was not authorized by SPF policy for '${spfDomain || fromDomain}'. Result: ${spfResult}.`,
      recommendation: 'Treat email as untrusted / spoofed.',
      mitreId: 'T1566.002',
    });
  }

  if (dkimResult === 'fail') {
    findings.push({
      id: 'dkim_failure',
      severity: 'high',
      title: 'DKIM Signature Invalid',
      detail: 'Cryptographic DKIM signature failed verification or message was modified in transit.',
      recommendation: 'Verify cryptographic headers and sender integrity.',
      mitreId: 'T1566.002',
    });
  }

  // 3. Reply-To Mismatch
  if (!fromReplyToMatch && replyToDomain) {
    findings.push({
      id: 'reply_to_mismatch',
      severity: 'medium',
      title: 'Reply-To Redirection Mismatch',
      detail: `Replies will be sent to '${replyToDomain}', which differs from the From domain '${fromDomain}'.`,
      recommendation: 'Inspect recipient of reply to ensure communications are not being covertly intercepted.',
      mitreId: 'T1566.002',
    });
  }

  // 4. Abnormal Transit Delays
  const anomalousHops = mtaHops.filter((h) => h.delayAnomaly);
  if (anomalousHops.length > 0) {
    findings.push({
      id: 'mta_delay_anomaly',
      severity: 'medium',
      title: 'Abnormal MTA Transit Delay',
      detail: `Hop ${anomalousHops[0].hop} experienced an anomalous delivery latency of ${anomalousHops[0].delayHuman}.`,
      recommendation: 'Review transit route for unauthorized intermediate queuing or greylisting.',
    });
  }

  // 5. Link Discrepancies
  const deceptiveLinks = linkDiscrepancies.filter((l) => l.status === 'DECEPTIVE MISMATCH');
  if (deceptiveLinks.length > 0) {
    findings.push({
      id: 'deceptive_hyperlink',
      severity: 'high',
      title: 'Deceptive Hyperlink Masking',
      detail: `${deceptiveLinks.length} hyperlink(s) show legitimate display text but navigate to unrelated destination domains.`,
      recommendation: 'Extract destination URLs for sandboxing and do not click in live browser.',
      mitreId: 'T1566.002',
    });
  }

  // 6. Urgency finding
  if (urgencyScore >= 40) {
    findings.push({
      id: 'social_engineering_urgency',
      severity: 'medium',
      title: 'Psychological Urgency / Pressure Trigger',
      detail: `Contains high-pressure keywords: ${detectedCategories.map((c) => c.terms.join(', ')).join('; ')}.`,
      recommendation: 'Warn recipient against impulsive action and verify request through out-of-band channel.',
      mitreId: 'T1566.001',
    });
  }

  // Calculate composite risk score
  const severityWeights = { high: 35, medium: 18, low: 7, info: 0 };
  const rawRisk = findings.reduce((acc, f) => acc + (severityWeights[f.severity] || 0), 0) + (urgencyScore > 50 ? 15 : 0);
  const riskScore = Math.min(100, Math.max(0, rawRisk));

  let verdict: ParsedEmailForensics['verdict'] = 'low_risk';
  const highFindings = findings.filter((f) => f.severity === 'high').length;
  const medFindings = findings.filter((f) => f.severity === 'medium').length;

  if (highFindings >= 2 || riskScore >= 70) verdict = 'malicious';
  else if (highFindings >= 1 || medFindings >= 2 || riskScore >= 40) verdict = 'suspicious';
  else if (medFindings >= 1 || riskScore >= 15) verdict = 'needs_review';

  return {
    headers: {
      from: rawFrom,
      fromDisplayName: fromInfo.displayName,
      fromAddress: fromInfo.address,
      replyTo: rawReplyTo || null,
      returnPath: rawReturnPath || null,
      to: rawTo || null,
      subject,
      date: dateStr,
      messageId,
      mailer,
    },
    domains: {
      fromDomain,
      replyToDomain,
      returnPathDomain,
      fromReplyToMatch,
      fromReturnPathMatch,
    },
    auth: authQuad,
    mtaHops,
    linkDiscrepancies,
    urgency: {
      score: urgencyScore,
      level: urgencyLevel,
      categories: detectedCategories,
    },
    findings,
    riskScore,
    verdict,
  };
}
