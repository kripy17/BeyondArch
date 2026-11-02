/** Deterministic identity for investigation objects (PROVENANCE_MODEL §9.3). */
export function fnv1a(str: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/** Deterministic id from a namespace prefix + stable content keys. */
export function objectId(prefix: string, ...parts: string[]): string {
  return fnv1a([prefix, ...parts].join("|"));
}