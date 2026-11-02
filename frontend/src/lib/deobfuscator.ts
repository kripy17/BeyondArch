/**
 * De-obfuscation Engine for DFIR analysts.
 * Supports rapid in-browser decoding of common adversary evasion techniques:
 * - PowerShell UTF-16LE Base64 (-EncodedCommand)
 * - Standard UTF-8 Base64 payloads
 * - URL percent-encoding (%20, %2e, etc.)
 * - Hex escapes (\x41, 0x41, continuous hex)
 * - ROT13 Caesar ciphers
 * - CyberChef pivot link generation
 */

export interface ObfuscationCandidate {
  type: "powershell" | "base64" | "url" | "hex" | "rot13";
  label: string;
  description: string;
  matchedText: string;
  decoded: string;
}

/**
 * Normalizes URL-safe and unpadded Base64 to standard Base64.
 */
function normalizeBase64(str: string): string {
  let cleaned = str.trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  while (cleaned.length % 4 !== 0) {
    cleaned += "=";
  }
  return cleaned;
}

/**
 * Safely decodes base64 string to a Uint8Array byte buffer.
 */
function base64ToBytes(b64: string): Uint8Array | null {
  try {
    const normalized = normalizeBase64(b64);
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) return null;
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

/**
 * Decodes PowerShell Base64 EncodedCommand (UTF-16LE).
 */
export function decodePowerShell(b64: string): string {
  const bytes = base64ToBytes(b64);
  if (!bytes || bytes.length === 0) return "";
  try {
    const decoder = new TextDecoder("utf-16le");
    return decoder.decode(bytes);
  } catch {
    return "";
  }
}

/**
 * Decodes standard Base64 (UTF-8).
 */
export function decodeBase64(b64: string): string {
  const bytes = base64ToBytes(b64);
  if (!bytes || bytes.length === 0) return "";
  try {
    const decoder = new TextDecoder("utf-8");
    return decoder.decode(bytes);
  } catch {
    return "";
  }
}

/**
 * Decodes URL percent-encoding (%20, %2f, %3a, etc.).
 */
export function decodeUrl(str: string): string {
  try {
    return decodeURIComponent(str.replace(/\+/g, " "));
  } catch {
    // Fallback: decode individual valid escape sequences
    return str.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => {
      try {
        return String.fromCharCode(parseInt(hex, 16));
      } catch {
        return `%${hex}`;
      }
    });
  }
}

/**
 * Decodes Hex byte strings (\x41\x42, 0x41 0x42, or continuous hex).
 */
export function decodeHex(hex: string): string {
  const cleaned = hex.trim();
  // Format 1: \x41\x42\x43
  if (/\\x[0-9a-fA-F]{2}/i.test(cleaned)) {
    return cleaned.replace(/\\x([0-9a-fA-F]{2})/gi, (_, byte) => String.fromCharCode(parseInt(byte, 16)));
  }
  // Format 2: 0x41, 0x42, 0x43 or 0x41 0x42
  if (/0x[0-9a-fA-F]{2}/i.test(cleaned)) {
    return cleaned.replace(/0x([0-9a-fA-F]{2})[,\s]*/gi, (_, byte) => String.fromCharCode(parseInt(byte, 16)));
  }
  // Format 3: Continuous hex characters (length >= 4 and even)
  const bare = cleaned.replace(/[^0-9a-fA-F]/g, "");
  if (bare.length >= 4 && bare.length % 2 === 0) {
    let out = "";
    for (let i = 0; i < bare.length; i += 2) {
      out += String.fromCharCode(parseInt(bare.slice(i, i + 2), 16));
    }
    return out;
  }
  return cleaned;
}

/**
 * Decodes ROT13 cipher.
 */
export function decodeRot13(str: string): string {
  return str.replace(/[a-zA-Z]/g, (c) => {
    const code = c.charCodeAt(0);
    const base = code >= 97 ? 97 : 65;
    return String.fromCharCode(((code - base + 13) % 26) + base);
  });
}

/**
 * Reverses text string.
 */
export function reverseText(str: string): string {
  return Array.from(str).reverse().join("");
}

/**
 * Checks if a string contains readable ASCII text (printable characters).
 */
function isReadableAscii(str: string, minRatio = 0.75): boolean {
  if (!str || str.length < 3) return false;
  let printable = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    // Allow tab, newline, carriage return, and printable range 32-126
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code <= 126)) {
      printable++;
    }
  }
  return printable / str.length >= minRatio;
}

/**
 * Scans input text and detects potential obfuscated payloads.
 */
export function detectObfuscation(text: string): ObfuscationCandidate[] {
  const candidates: ObfuscationCandidate[] = [];
  const t = text.trim();
  if (!t) return candidates;

  // 1. PowerShell EncodedCommand
  const psMatch = t.match(/(?:powershell(?:\.exe)?.*)?(?:-(?:encodedcommand|enc|ec|e))\s+([A-Za-z0-9+/=]{4,})/i);
  if (psMatch && psMatch[1]) {
    const decoded = decodePowerShell(psMatch[1]);
    if (decoded && isReadableAscii(decoded)) {
      candidates.push({
        type: "powershell",
        label: "PowerShell EncodedCommand",
        description: "UTF-16LE Base64 encoded PowerShell command",
        matchedText: psMatch[0],
        decoded,
      });
    }
  }

  // 2. URL percent encoding
  const urlEncCount = (t.match(/%[0-9A-Fa-f]{2}/g) ?? []).length;
  if (urlEncCount >= 2) {
    const decoded = decodeUrl(t);
    if (decoded !== t) {
      candidates.push({
        type: "url",
        label: "URL Encoded String",
        description: `${urlEncCount} percent-encoded byte sequences`,
        matchedText: t.slice(0, 80) + (t.length > 80 ? "…" : ""),
        decoded,
      });
    }
  }

  // 3. Hex escapes (\x41 or 0x41)
  const hexEscapeMatch = t.match(/(?:\\x[0-9a-fA-F]{2}){2,}|(?:0x[0-9a-fA-F]{2}[,\s]*){2,}/);
  if (hexEscapeMatch) {
    const decoded = decodeHex(hexEscapeMatch[0]);
    if (decoded && isReadableAscii(decoded)) {
      candidates.push({
        type: "hex",
        label: "Hex Escaped Bytes",
        description: "Hexadecimal byte representation",
        matchedText: hexEscapeMatch[0].slice(0, 60) + (hexEscapeMatch[0].length > 60 ? "…" : ""),
        decoded,
      });
    }
  }

  // 4. Raw Base64 payloads (if not already captured as PowerShell)
  if (!candidates.some((c) => c.type === "powershell")) {
    const b64Tokens = t.match(/\b[A-Za-z0-9+/]{24,}={0,2}\b/g);
    if (b64Tokens) {
      for (const token of b64Tokens.slice(0, 2)) {
        // Test UTF-8 first
        const utf8 = decodeBase64(token);
        if (utf8 && isReadableAscii(utf8) && utf8.length >= 8) {
          candidates.push({
            type: "base64",
            label: "Base64 (UTF-8) Payload",
            description: "Standard Base64 encoded text",
            matchedText: token.slice(0, 40) + (token.length > 40 ? "…" : ""),
            decoded: utf8,
          });
          break;
        }
        // Test UTF-16LE
        const utf16 = decodePowerShell(token);
        if (utf16 && isReadableAscii(utf16) && utf16.length >= 8) {
          candidates.push({
            type: "powershell",
            label: "Base64 (UTF-16LE) Payload",
            description: "Windows Unicode Base64 encoded payload",
            matchedText: token.slice(0, 40) + (token.length > 40 ? "…" : ""),
            decoded: utf16,
          });
          break;
        }
      }
    }
  }

  return candidates;
}

/**
 * Builds a direct CyberChef URL with input and optional recipe.
 */
export function generateCyberChefUrl(input: string, recipe = "Magic(3,false,false,'')"): string {
  try {
    const encodedInput = btoa(encodeURIComponent(input).replace(/%([0-9A-F]{2})/g, (_, p1) =>
      String.fromCharCode(parseInt(p1, 16))
    ));
    return `https://gchq.github.io/CyberChef/#recipe=${encodeURIComponent(recipe)}&input=${encodeURIComponent(encodedInput)}`;
  } catch {
    return `https://gchq.github.io/CyberChef/#recipe=${encodeURIComponent(recipe)}`;
  }
}
