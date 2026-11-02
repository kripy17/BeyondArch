/**
 * Shannon Entropy calculation and classification for binary/text data.
 * Scale: 0.0 (uniform/repetitive) to 8.0 (completely random / encrypted).
 */

export type EntropyClassification = "empty" | "low" | "normal" | "high" | "very_high";

export interface EntropyResult {
  entropy: number;            // 0.00 to 8.00
  percentage: number;         // 0 to 100%
  byteLength: number;
  classification: EntropyClassification;
  label: string;
  description: string;
  isSuspicious: boolean;      // entropy >= 7.0 (likely encrypted, packed, or high-entropy key)
  badgeColor: string;
  topBytes: { byte: number; hex: string; char: string; count: number; percent: number }[];
}

export function calculateEntropy(input: string): EntropyResult {
  if (!input || input.length === 0) {
    return {
      entropy: 0,
      percentage: 0,
      byteLength: 0,
      classification: "empty",
      label: "Empty",
      description: "No data to analyze",
      isSuspicious: false,
      badgeColor: "border-muted text-muted-foreground bg-muted/20",
      topBytes: [],
    };
  }

  // If all characters fit in 1 byte (e.g. binary/latin1/ASCII strings), treat directly as bytes
  let isLatin1 = true;
  for (let i = 0; i < input.length; i++) {
    if (input.charCodeAt(i) > 255) {
      isLatin1 = false;
      break;
    }
  }

  let bytes: Uint8Array;
  if (isLatin1) {
    bytes = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i++) {
      bytes[i] = input.charCodeAt(i) & 0xff;
    }
  } else {
    bytes = new TextEncoder().encode(input);
  }
  const length = bytes.length;

  const frequencies = new Map<number, number>();
  for (let i = 0; i < length; i++) {
    const b = bytes[i];
    frequencies.set(b, (frequencies.get(b) || 0) + 1);
  }


  let entropy = 0;
  for (const count of frequencies.values()) {
    const p = count / length;
    entropy -= p * Math.log2(p);
  }

  entropy = Math.round(entropy * 1000) / 1000;
  const percentage = Math.min(100, Math.round((entropy / 8.0) * 100));

  let classification: EntropyClassification;
  let label: string;
  let description: string;
  let badgeColor: string;

  if (entropy < 3.2) {
    classification = "low";
    label = "Low Entropy";
    description = "Repetitive or sparse text pattern";
    badgeColor = "border-info/30 text-info bg-info/10";
  } else if (entropy < 5.2) {
    classification = "normal";
    label = "Normal / Plaintext";
    description = "Natural language text or structured source code";
    badgeColor = "border-success/30 text-success bg-success/10";
  } else if (entropy < 7.1) {
    classification = "high";
    label = "High / Obfuscated";
    description = "Compressed data, base64 blob, or obfuscated script";
    badgeColor = "border-warning/30 text-warning bg-warning/10";
  } else {
    classification = "very_high";
    label = "Very High / Encrypted";
    description = "Heavily packed, encrypted payload, or cryptographic key";
    badgeColor = "border-destructive/30 text-destructive bg-destructive/10";
  }

  // Top 5 most frequent bytes
  const sorted = Array.from(frequencies.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([byte, count]) => {
      const hex = "0x" + byte.toString(16).padStart(2, "0");
      const char = byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".";
      return {
        byte,
        hex,
        char,
        count,
        percent: Math.round((count / length) * 1000) / 10,
      };
    });

  return {
    entropy,
    percentage,
    byteLength: length,
    classification,
    label,
    description,
    isSuspicious: entropy >= 7.0,
    badgeColor,
    topBytes: sorted,
  };
}
