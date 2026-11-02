/**
 * Client-Side Single-Byte XOR Brute Force Search
 * Evaluates all 256 keys ($0x00 - $0xFF$), ranking candidates by printable ASCII ratio,
 * English character frequencies, or priority needle matching.
 */

export interface XorCandidate {
  key: number;
  keyHex: string;
  score: number;
  asciiRatio: number;
  hasNeedle: boolean;
  preview: string;
}

const ENGLISH_CHARS = new Set("etaoinshrdlcumwfgypbvkjxqzETAOINSHRDLCUMWFGYPBVKJXQZ 0123456789\r\n\t.,;:!?-_/\\'\"()[]{}");

export function xorBruteForce(
  input: string,
  topK: number = 5,
  knownPlaintext?: string
): XorCandidate[] {
  if (!input || input.trim().length === 0) return [];

  const trimmed = input.trim();
  let rawBytes: Uint8Array;

  // Check if input is hex-encoded
  const cleanHex = trimmed.replace(/[\s,:-]+/g, "");
  if (/^[0-9a-fA-F]+$/.test(cleanHex) && cleanHex.length % 2 === 0) {
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < cleanHex.length; i += 2) {
      bytes[i / 2] = parseInt(cleanHex.slice(i, i + 2), 16);
    }
    rawBytes = bytes;
  } else {
    // Treat as raw characters
    const bytes = new Uint8Array(trimmed.length);
    for (let i = 0; i < trimmed.length; i++) {
      bytes[i] = trimmed.charCodeAt(i) & 0xff;
    }
    rawBytes = bytes;
  }

  if (rawBytes.length === 0) return [];

  const needleLower = knownPlaintext ? knownPlaintext.trim().toLowerCase() : null;
  const candidates: XorCandidate[] = [];
  const len = rawBytes.length;

  for (let key = 0; key < 256; key++) {
    let printableCount = 0;
    let englishCount = 0;
    const decodedChars: string[] = [];

    for (let i = 0; i < len; i++) {
      const b = rawBytes[i] ^ key;
      const ch = String.fromCharCode(b);
      decodedChars.push(ch);

      if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) {
        printableCount++;
      }
      if (ENGLISH_CHARS.has(ch)) {
        englishCount++;
      }
    }

    const asciiRatio = printableCount / len;
    let score = (asciiRatio * 0.6) + ((englishCount / len) * 0.4);

    const fullDecoded = decodedChars.join("");
    let hasNeedle = false;

    if (needleLower && fullDecoded.toLowerCase().includes(needleLower)) {
      hasNeedle = true;
      score += 10.0; // Dominant prioritization for needle
    }

    candidates.push({
      key,
      keyHex: "0x" + key.toString(16).padStart(2, "0"),
      score: Math.round(score * 1000) / 1000,
      asciiRatio: Math.round(asciiRatio * 1000) / 10,
      hasNeedle,
      preview: fullDecoded.slice(0, 300),
    });
  }

  candidates.sort((a, b) => {
    if (a.hasNeedle !== b.hasNeedle) return a.hasNeedle ? -1 : 1;
    return b.score - a.score;
  });

  return candidates.slice(0, topK);
}
