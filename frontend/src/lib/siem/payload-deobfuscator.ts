export interface DeobfuscatedPayload {
  rawMatch: string;
  decodedText: string;
  encoding: "utf-16le" | "utf-8" | "url";
  extractedObservables: {
    urls: string[];
    ips: string[];
    commands: string[];
  };
}

/**
 * Checks if a string contains Base64 or obfuscated command lines,
 * and decodes them with UTF-16LE (PowerShell -EncodedCommand) or UTF-8.
 */
export function detectAndDeobfuscate(text: string): DeobfuscatedPayload | null {
  if (!text) return null;

  // 1. Check for PowerShell EncodedCommand / -enc
  const psMatch = text.match(/(?:-EncodedCommand|-enc\b|-Encoded\b|EncodedCommand[:= ]+)\s*([A-Za-z0-9+/=]{16,})/i);
  if (psMatch && psMatch[1]) {
    const b64 = psMatch[1].trim();
    const decoded = decodeBase64Utf16Le(b64);
    if (decoded && isPrintable(decoded)) {
      return buildPayload(psMatch[0], decoded, "utf-16le");
    }
  }

  // 2. Check for generic Base64 blobs of length >= 24
  const b64Match = text.match(/\b([A-Za-z0-9+/]{24,}={0,2})\b/);
  if (b64Match && b64Match[1]) {
    const b64 = b64Match[1].trim();
    // Try UTF-16LE first (common in Windows logs)
    const utf16 = decodeBase64Utf16Le(b64);
    if (utf16 && isPrintable(utf16) && utf16.length > 5) {
      return buildPayload(b64, utf16, "utf-16le");
    }
    // Then try UTF-8 / ASCII
    const utf8 = decodeBase64Utf8(b64);
    if (utf8 && isPrintable(utf8) && utf8.length > 5) {
      return buildPayload(b64, utf8, "utf-8");
    }
  }

  // 3. Check for URL percent encoding with directory traversal or script tags
  if (/%(?:2f|2e|3c|3e|20|22)/i.test(text)) {
    try {
      const unescaped = decodeURIComponent(text);
      if (unescaped !== text) {
        return buildPayload(text, unescaped, "url");
      }
    } catch {
      // ignore
    }
  }

  return null;
}

function decodeBase64Utf16Le(b64: string): string | null {
  try {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const decoder = new TextDecoder("utf-16le", { fatal: false });
    const text = decoder.decode(bytes);
    return text.replace(/\0/g, "");
  } catch {
    return null;
  }
}

function decodeBase64Utf8(b64: string): string | null {
  try {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const decoder = new TextDecoder("utf-8", { fatal: false });
    return decoder.decode(bytes);
  } catch {
    return null;
  }
}

function isPrintable(str: string): boolean {
  if (!str || str.length < 3) return false;
  let printable = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13) {
      printable++;
    }
  }
  return printable / str.length > 0.85;
}

function buildPayload(raw: string, decoded: string, encoding: DeobfuscatedPayload["encoding"]): DeobfuscatedPayload {
  const urlRx = /https?:\/\/[^\s"'`<>]+/gi;
  const ipRx = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
  const cmdRx = /\b(powershell|cmd|wmic|certutil|bitsadmin|mshta|rundll32|regsvr32|curl|wget|iex|invoke-expression|downloadstring|start-process)\b/gi;

  const urls = [...new Set(decoded.match(urlRx) || [])];
  const ips = [...new Set(decoded.match(ipRx) || [])];
  const commands = [...new Set(decoded.match(cmdRx) || [])];

  return {
    rawMatch: raw,
    decodedText: decoded,
    encoding,
    extractedObservables: {
      urls,
      ips,
      commands,
    },
  };
}
