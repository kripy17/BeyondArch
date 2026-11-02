// Pure TypeScript URL Dissector & Forensic Analysis Engine
// Inspired by urlscan.io, Cisco Talos, VirusTotal, and URLhaus

export interface QueryParamInfo {
  key: string;
  value: string;
  isEncoded: boolean;
  decodedValue: string;
  isUrl: boolean;
  isRedirectTarget: boolean;
}

export interface ConfusableChar {
  char: string;
  codePoint: string;
  script: string;
  lookalikeLatin: string;
  position: number;
}

export interface HomographResult {
  isPunycode: boolean;
  punycodeAscii: string;
  unicodeString: string;
  hasConfusables: boolean;
  isMixedScript: boolean;
  confusableChars: ConfusableChar[];
  impersonatedBrand: string | null;
}

export interface RedirectHop {
  hop: number;
  url: string;
  host: string;
  statusCode: number;
  statusText: string;
  hopType: 'initial' | 'shortener' | 'open_redirect' | 'destination';
  notes: string;
}

export interface UrlSignal {
  id: string;
  label: string;
  severity: 'high' | 'medium' | 'low' | 'info';
  evidence: string;
  explanation: string;
  mitreId?: string;
}

export interface UrlAnatomy {
  originalUrl: string;
  refangedUrl: string;
  normalizedUrl: string;
  scheme: string;
  username: string | null;
  password: string | null;
  host: string;
  subdomain: string;
  subdomains: string[];
  apexDomain: string;
  tld: string;
  port: number | null;
  portCategory: 'standard_http' | 'standard_https' | 'c2_suspicious' | 'common_alt' | 'unusual';
  path: string;
  pathSegments: string[];
  query: string;
  queryParams: QueryParamInfo[];
  fragment: string;
  entropy: {
    fullUrl: number;
    path: number;
    query: number;
    maxSegment: number;
  };
  signals: UrlSignal[];
  riskScore: number;
  verdict: 'malicious' | 'suspicious' | 'needs_review' | 'low_risk';
  homograph: HomographResult;
  brandImpersonation: {
    detectedBrand: string | null;
    matchedTerms: string[];
    mismatchReason: string | null;
  };
  redirectChain: RedirectHop[];
}

// RFC 3492 Punycode decoder
export function decodePunycode(input: string): string {
  const base = 36;
  const tmin = 1;
  const tmax = 26;
  const skew = 38;
  const damp = 700;
  const initialBias = 72;
  const initialN = 128;
  const delimiter = '-';

  function adapt(delta: number, numpoints: number, firsttime: boolean): number {
    let k = 0;
    delta = firsttime ? Math.floor(delta / damp) : Math.floor(delta / 2);
    delta += Math.floor(delta / numpoints);
    for (; delta > Math.floor(((base - tmin) * tmax) / 2); k += base) {
      delta = Math.floor(delta / (base - tmin));
    }
    return Math.floor(k + ((base - tmin + 1) * delta) / (delta + skew));
  }

  const output: number[] = [];
  const basicLen = input.lastIndexOf(delimiter);
  let pos = 0;
  if (basicLen > 0) {
    for (; pos < basicLen; ++pos) {
      output.push(input.charCodeAt(pos));
    }
    pos++; // skip delimiter
  }

  let n = initialN;
  let i = 0;
  let bias = initialBias;

  while (pos < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (pos >= input.length) throw new Error('Invalid punycode string');
      const charCode = input.charCodeAt(pos++);
      let digit: number;
      if (charCode - 48 < 10) digit = charCode - 22;
      else if (charCode - 65 < 26) digit = charCode - 65;
      else if (charCode - 97 < 26) digit = charCode - 97;
      else throw new Error('Invalid punycode char');

      i += digit * w;
      const t = k <= bias ? tmin : k >= bias + tmax ? tmax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }

    const outLen = output.length + 1;
    bias = adapt(i - oldi, outLen, oldi === 0);
    n += Math.floor(i / outLen);
    i %= outLen;
    output.splice(i, 0, n);
    i++;
  }

  return String.fromCodePoint(...output);
}

export function toUnicodeDomain(domain: string): string {
  return domain
    .split('.')
    .map((part) => {
      if (part.toLowerCase().startsWith('xn--')) {
        try {
          return decodePunycode(part.slice(4).toLowerCase());
        } catch {
          return part;
        }
      }
      return part;
    })
    .join('.');
}

// Shannon entropy calculation
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

// Defang / Refang utilities
export function refangUrl(url: string): string {
  let res = url.trim();
  res = res.replace(/hxxp/gi, 'http');
  res = res.replace(/\[\.\]|\(\.\)|\{\.\}/g, '.');
  res = res.replace(/\[:\]/g, ':');
  res = res.replace(/\[@\]|\[at\]|\(at\)/gi, '@');
  return res;
}

export function defangUrl(url: string): string {
  let res = url.trim();
  res = res.replace(/^https:\/\//i, 'hxxps://');
  res = res.replace(/^http:\/\//i, 'hxxp://');
  res = res.replace(/\./g, '[.]');
  res = res.replace(/:(\d+)/g, '[:]$1');
  return res;
}

// Confusable table mapping Unicode code points to Latin characters
const CONFUSABLES: Record<number, { latin: string; script: string }> = {
  // Cyrillic lowercase
  0x0430: { latin: 'a', script: 'Cyrillic' },
  0x0441: { latin: 'c', script: 'Cyrillic' },
  0x0435: { latin: 'e', script: 'Cyrillic' },
  0x043E: { latin: 'o', script: 'Cyrillic' },
  0x0440: { latin: 'p', script: 'Cyrillic' },
  0x0455: { latin: 's', script: 'Cyrillic' },
  0x0445: { latin: 'x', script: 'Cyrillic' },
  0x0443: { latin: 'y', script: 'Cyrillic' },
  0x0456: { latin: 'i', script: 'Cyrillic' },
  0x0458: { latin: 'j', script: 'Cyrillic' },
  // Cyrillic uppercase
  0x0410: { latin: 'A', script: 'Cyrillic' },
  0x0412: { latin: 'B', script: 'Cyrillic' },
  0x0421: { latin: 'C', script: 'Cyrillic' },
  0x0415: { latin: 'E', script: 'Cyrillic' },
  0x041D: { latin: 'H', script: 'Cyrillic' },
  0x041A: { latin: 'K', script: 'Cyrillic' },
  0x041C: { latin: 'M', script: 'Cyrillic' },
  0x041E: { latin: 'O', script: 'Cyrillic' },
  0x0420: { latin: 'P', script: 'Cyrillic' },
  0x0422: { latin: 'T', script: 'Cyrillic' },
  0x0425: { latin: 'X', script: 'Cyrillic' },
  // Greek lowercase
  0x03BF: { latin: 'o', script: 'Greek' },
  0x03BD: { latin: 'v', script: 'Greek' },
  0x03C1: { latin: 'p', script: 'Greek' },
  0x03B9: { latin: 'i', script: 'Greek' },
  0x03BA: { latin: 'k', script: 'Greek' },
  // Greek uppercase
  0x0391: { latin: 'A', script: 'Greek' },
  0x0392: { latin: 'B', script: 'Greek' },
  0x0395: { latin: 'E', script: 'Greek' },
  0x0397: { latin: 'H', script: 'Greek' },
  0x0399: { latin: 'I', script: 'Greek' },
  0x039A: { latin: 'K', script: 'Greek' },
  0x039C: { latin: 'M', script: 'Greek' },
  0x039D: { latin: 'N', script: 'Greek' },
  0x039F: { latin: 'O', script: 'Greek' },
  0x03A1: { latin: 'P', script: 'Greek' },
  0x03A4: { latin: 'T', script: 'Greek' },
  0x03A7: { latin: 'X', script: 'Greek' },
};

const KNOWN_BRANDS = [
  'microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint', 'teams', 'google', 'gmail',
  'paypal', 'apple', 'icloud', 'amazon', 'netflix', 'facebook', 'instagram', 'whatsapp',
  'linkedin', 'github', 'dropbox', 'docusign', 'adobe', 'okta', 'duo', 'slack', 'zoom',
  'chase', 'wellsfargo', 'bankofamerica', 'dhl', 'fedex', 'ups', 'usps', 'steam', 'coinbase', 'binance',
];

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'ru', 'cn', 'work', 'click', 'link', 'buzz',
  'monster', 'rest', 'fit', 'icu', 'cam', 'surf', 'loan', 'tokyo', 'racing', 'download',
]);

const SUSPICIOUS_EXTENSIONS = new Set([
  '.exe', '.scr', '.js', '.jse', '.vbs', '.vbe', '.hta', '.bat', '.cmd', '.ps1',
  '.jar', '.msi', '.lnk', '.iso', '.img', '.zip', '.rar', '.7z', '.docm', '.xlsm',
]);

const OPEN_REDIRECT_PARAMS = new Set([
  'redirect', 'url', 'next', 'dest', 'destination', 'target', 'return', 'return_url',
  'continue', 'goto', 'link', 'r', 'u', 'forward', 'out',
]);

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do',
  'mcaf.ee', 'rebrand.ly', 'cutt.ly', 's.id', 'shorturl.at',
]);

// Helper to extract apex domain & TLD
function parseDomainParts(hostname: string): { subdomain: string; subdomains: string[]; apexDomain: string; tld: string } {
  const parts = hostname.toLowerCase().split('.');
  if (parts.length <= 1) {
    return { subdomain: '', subdomains: [], apexDomain: hostname, tld: '' };
  }
  // Check for multi-part ccTLDs like co.uk, com.au, co.in
  const secondLevelTlds = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac']);
  let tldParts = 1;
  if (parts.length >= 3 && secondLevelTlds.has(parts[parts.length - 2]) && parts[parts.length - 1].length === 2) {
    tldParts = 2;
  }
  const tld = parts.slice(parts.length - tldParts).join('.');
  const apexDomain = parts.slice(parts.length - tldParts - 1).join('.');
  const subparts = parts.slice(0, parts.length - tldParts - 1);
  return {
    subdomain: subparts.join('.'),
    subdomains: subparts,
    apexDomain,
    tld,
  };
}

// Main dissection function
export function dissectUrl(rawInput: string): UrlAnatomy {
  const refanged = refangUrl(rawInput);
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(refanged.includes('://') ? refanged : `https://${refanged}`);
  } catch {
    // Fallback pseudo-parse
    parsedUrl = new URL(`https://${refanged.replace(/^[^/]+:\/\//, '')}`);
  }

  const scheme = parsedUrl.protocol.replace(':', '').toLowerCase();
  const username = parsedUrl.username || null;
  const password = parsedUrl.password || null;
  const host = parsedUrl.hostname.toLowerCase();
  const { subdomain, subdomains, apexDomain, tld } = parseDomainParts(host);

  // Port categorization
  let port: number | null = null;
  if (parsedUrl.port) {
    port = parseInt(parsedUrl.port, 10);
  }
  let portCategory: UrlAnatomy['portCategory'] = 'standard_https';
  if (!port) {
    portCategory = scheme === 'http' ? 'standard_http' : 'standard_https';
  } else if (port === 80) {
    portCategory = 'standard_http';
  } else if (port === 443) {
    portCategory = 'standard_https';
  } else if ([8080, 8443, 8000, 8888].includes(port)) {
    portCategory = 'common_alt';
  } else if ([1337, 4444, 9001, 6667, 31337, 7070, 5555].includes(port)) {
    portCategory = 'c2_suspicious';
  } else {
    portCategory = 'unusual';
  }

  // Path & Segments
  const path = parsedUrl.pathname || '/';
  const pathSegments = path.split('/').filter(Boolean);

  // Query & Params
  const query = parsedUrl.search ? parsedUrl.search.slice(1) : '';
  const queryParams: QueryParamInfo[] = [];
  const openRedirectTargets: string[] = [];

  if (query) {
    const searchParams = new URLSearchParams(query);
    searchParams.forEach((val, key) => {
      const isEncoded = /%[0-9a-f]{2}/i.test(val);
      let decoded = val;
      try {
        decoded = decodeURIComponent(val);
      } catch {
        decoded = val;
      }
      const isUrl = /^https?:\/\//i.test(decoded) || /^\/\//i.test(decoded);
      const isRedirectTarget = OPEN_REDIRECT_PARAMS.has(key.toLowerCase()) || isUrl;
      if (isRedirectTarget && isUrl) {
        openRedirectTargets.push(decoded);
      }
      queryParams.push({
        key,
        value: val,
        isEncoded,
        decodedValue: decoded,
        isUrl,
        isRedirectTarget,
      });
    });
  }

  const fragment = parsedUrl.hash ? parsedUrl.hash.slice(1) : '';

  // Shannon Entropy calculations
  const fullEntropy = calculateShannonEntropy(rawInput);
  const pathEntropy = calculateShannonEntropy(path);
  const queryEntropy = calculateShannonEntropy(query);
  const segmentEntropies = pathSegments.map((s) => calculateShannonEntropy(s));
  const maxSegment = segmentEntropies.length ? Math.max(...segmentEntropies) : 0;

  // Homograph / Punycode Analysis
  const isPunycode = host.includes('xn--');
  const unicodeDomain = toUnicodeDomain(host);
  const confusableChars: ConfusableChar[] = [];
  let isMixedScript = false;
  let hasLatin = false;
  let hasNonLatin = false;

  for (let idx = 0; idx < unicodeDomain.length; idx++) {
    const cp = unicodeDomain.codePointAt(idx)!;
    if (cp > 0xffff) idx++; // surrogate pair
    if ((cp >= 65 && cp <= 90) || (cp >= 97 && cp <= 122)) {
      hasLatin = true;
    } else if (cp > 127 && cp !== 46 && cp !== 45) {
      hasNonLatin = true;
    }
    if (CONFUSABLES[cp]) {
      confusableChars.push({
        char: String.fromCodePoint(cp),
        codePoint: `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`,
        script: CONFUSABLES[cp].script,
        lookalikeLatin: CONFUSABLES[cp].latin,
        position: idx,
      });
    }
  }
  isMixedScript = hasLatin && hasNonLatin;

  // Detect impersonated brand in homograph
  let impersonatedBrand: string | null = null;
  const normalizedUnicode = unicodeDomain
    .split('')
    .map((ch) => {
      const cp = ch.codePointAt(0)!;
      return CONFUSABLES[cp] ? CONFUSABLES[cp].latin : ch;
    })
    .join('');

  for (const brand of KNOWN_BRANDS) {
    if (normalizedUnicode.includes(brand) && !apexDomain.includes(brand)) {
      impersonatedBrand = brand;
      break;
    }
  }

  const homograph: HomographResult = {
    isPunycode,
    punycodeAscii: host,
    unicodeString: unicodeDomain,
    hasConfusables: confusableChars.length > 0,
    isMixedScript,
    confusableChars,
    impersonatedBrand,
  };

  // Brand Impersonation in standard URL
  const loweredUrl = rawInput.toLowerCase();
  const matchedBrands: string[] = [];
  for (const brand of KNOWN_BRANDS) {
    if (loweredUrl.includes(brand)) {
      matchedBrands.push(brand);
    }
  }
  let brandDetected: string | null = null;
  let mismatchReason: string | null = null;
  if (matchedBrands.length > 0) {
    brandDetected = matchedBrands[0];
    const isLegitApex = apexDomain.includes(brandDetected);
    if (!isLegitApex) {
      mismatchReason = `Brand '${brandDetected}' appears in URL, but the apex domain is '${apexDomain}'.`;
    }
  }

  // Signals and Risk Scoring
  const signals: UrlSignal[] = [];

  if (isPunycode || confusableChars.length > 0) {
    signals.push({
      id: 'punycode_homograph',
      label: 'IDN / Homograph Impersonation',
      severity: 'high',
      evidence: `${host} -> ${unicodeDomain}`,
      explanation: 'Uses Internationalized Domain Name or confusable Unicode characters to impersonate legitimate domains.',
      mitreId: 'T1566.002',
    });
  }

  if (mismatchReason) {
    signals.push({
      id: 'brand_impersonation',
      label: 'Brand Impersonation',
      severity: 'high',
      evidence: mismatchReason,
      explanation: 'Legitimate brand name detected on an unrelated registrable domain.',
      mitreId: 'T1566.002',
    });
  }

  if (username || password) {
    signals.push({
      id: 'embedded_credentials',
      label: 'Embedded Credentials in URL',
      severity: 'high',
      evidence: `${username || ''}:${password ? '***' : ''}@`,
      explanation: 'Userinfo credentials in URL can deceive users and conceal true destination host.',
      mitreId: 'T1566.002',
    });
  }

  if (portCategory === 'c2_suspicious') {
    signals.push({
      id: 'c2_port',
      label: 'Suspicious / C2 Port',
      severity: 'high',
      evidence: `Port ${port}`,
      explanation: 'Port is known for common command and control (C2) or interactive reverse shells.',
      mitreId: 'T1571',
    });
  } else if (portCategory === 'unusual' || portCategory === 'common_alt') {
    signals.push({
      id: 'unusual_port',
      label: 'Non-Standard Web Port',
      severity: 'medium',
      evidence: `Port ${port}`,
      explanation: 'Destination uses non-standard HTTP/HTTPS port.',
    });
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    signals.push({
      id: 'suspicious_tld',
      label: 'High-Abuse Top-Level Domain',
      severity: 'medium',
      evidence: `.${tld}`,
      explanation: 'TLD has high prevalence of malicious activity or disposable domains.',
      mitreId: 'T1566.002',
    });
  }

  // Extension check
  let suspiciousExt: string | null = null;
  const pathLower = path.toLowerCase();
  for (const ext of SUSPICIOUS_EXTENSIONS) {
    if (pathLower.endsWith(ext) || pathLower.includes(`${ext}/`)) {
      suspiciousExt = ext;
      break;
    }
  }
  if (suspiciousExt) {
    signals.push({
      id: 'executable_payload',
      label: 'Direct Executable / Payload Extension',
      severity: 'high',
      evidence: suspiciousExt,
      explanation: 'URL points directly to an executable, script, or container payload.',
      mitreId: 'T1204.002',
    });
  }

  if (openRedirectTargets.length > 0) {
    signals.push({
      id: 'open_redirect',
      label: 'Open Redirect Target Detected',
      severity: 'medium',
      evidence: openRedirectTargets[0],
      explanation: 'Query parameter directs client to external target, enabling phishing evasion.',
      mitreId: 'T1566.002',
    });
  }

  if (SHORTENERS.has(host)) {
    signals.push({
      id: 'url_shortener',
      label: 'URL Shortener Service',
      severity: 'medium',
      evidence: host,
      explanation: 'Hides true destination and redirects victim to final target.',
      mitreId: 'T1090',
    });
  }

  if (subdomains.length >= 3) {
    signals.push({
      id: 'deep_subdomains',
      label: 'Excessive Subdomain Depth',
      severity: 'low',
      evidence: `${subdomains.length} subdomains: ${subdomain}`,
      explanation: 'Adversaries stack subdomains to mimic legitimate enterprise URLs.',
    });
  }

  if (maxSegment > 4.5 || fullEntropy > 4.6) {
    signals.push({
      id: 'high_entropy',
      label: 'High Entropy Token / Identifier',
      severity: 'medium',
      evidence: `Entropy: ${Math.max(maxSegment, fullEntropy)} bits`,
      explanation: 'High Shannon randomness indicates cryptographic hashes, session tokens, or DGA naming.',
    });
  }

  if (scheme === 'http') {
    signals.push({
      id: 'cleartext_http',
      label: 'Unencrypted HTTP Protocol',
      severity: 'low',
      evidence: 'http://',
      explanation: 'Traffic is transmitted without TLS encryption.',
    });
  }

  // Calculate overall risk score & verdict
  const weights = { high: 35, medium: 18, low: 8, info: 0 };
  const rawScore = signals.reduce((acc, s) => acc + (weights[s.severity] || 0), 0);
  const riskScore = Math.min(100, rawScore);

  let verdict: UrlAnatomy['verdict'] = 'low_risk';
  const highCount = signals.filter((s) => s.severity === 'high').length;
  const medCount = signals.filter((s) => s.severity === 'medium').length;

  if (highCount >= 2 || riskScore >= 70) {
    verdict = 'malicious';
  } else if (highCount >= 1 || medCount >= 2 || riskScore >= 40) {
    verdict = 'suspicious';
  } else if (medCount >= 1 || riskScore >= 15) {
    verdict = 'needs_review';
  }

  // Redirect chain simulation
  const redirectChain: RedirectHop[] = [];
  redirectChain.push({
    hop: 1,
    url: parsedUrl.toString(),
    host,
    statusCode: SHORTENERS.has(host) || openRedirectTargets.length > 0 ? 302 : 200,
    statusText: SHORTENERS.has(host) || openRedirectTargets.length > 0 ? '302 Found' : '200 OK',
    hopType: SHORTENERS.has(host) ? 'shortener' : openRedirectTargets.length > 0 ? 'open_redirect' : 'destination',
    notes: SHORTENERS.has(host)
      ? 'Initial shortener entry point'
      : openRedirectTargets.length > 0
      ? 'Open redirect relay portal'
      : 'Landing page',
  });

  if (openRedirectTargets.length > 0) {
    try {
      const targetUrl = new URL(openRedirectTargets[0]);
      redirectChain.push({
        hop: 2,
        url: targetUrl.toString(),
        host: targetUrl.hostname,
        statusCode: 200,
        statusText: '200 OK',
        hopType: 'destination',
        notes: 'Final payload / credential harvest destination via open redirect',
      });
    } catch {
      // invalid target url string
    }
  } else if (SHORTENERS.has(host)) {
    // Simulated shortener landing
    redirectChain.push({
      hop: 2,
      url: `https://landing-auth.${apexDomain}/auth/session`,
      host: `landing-auth.${apexDomain}`,
      statusCode: 200,
      statusText: '200 OK',
      hopType: 'destination',
      notes: 'Final resolved target after shortener expansion',
    });
  }

  return {
    originalUrl: rawInput,
    refangedUrl: refanged,
    normalizedUrl: parsedUrl.toString(),
    scheme,
    username,
    password,
    host,
    subdomain,
    subdomains,
    apexDomain,
    tld,
    port,
    portCategory,
    path,
    pathSegments,
    query,
    queryParams,
    fragment,
    entropy: {
      fullUrl: fullEntropy,
      path: pathEntropy,
      query: queryEntropy,
      maxSegment,
    },
    signals,
    riskScore,
    verdict,
    homograph,
    brandImpersonation: {
      detectedBrand: brandDetected,
      matchedTerms: matchedBrands,
      mismatchReason,
    },
    redirectChain,
  };
}
