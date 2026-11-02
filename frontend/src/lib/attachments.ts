import type { Case, Entry } from "@/data/case";
import { crc32 } from "@/lib/zip";

/** File attachments on case entries, stored locally.
 *  Metadata rides on the entry (ba.cases.v2); payloads live in a separate
 *  localStorage bucket (ba.attachments.v1) so screenshots never bloat the
 *  case list. Everything is opt-in, local-only, and size-capped with honest
 *  errors — this is a practice workbench, not a document vault. */

export const LS_ATTACHMENTS = "ba.attachments.v1";
export const MAX_FILE_BYTES = 512 * 1024;
export const MAX_TOTAL_BYTES = 3 * 1024 * 1024;

export type EntryAttachment = {
  id: string;
  name: string;
  mime: string;
  size: number;
  addedAt: string;
};

type AttachmentPayload = { mime: string; b64: string };
type AttachmentStore = Record<string, AttachmentPayload>;

const urlCache = new Map<string, string>();

function loadStore(): AttachmentStore {
  try {
    const raw = localStorage.getItem(LS_ATTACHMENTS);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as AttachmentStore;
    return typeof parsed === "object" && parsed ? parsed : {};
  } catch { return {}; }
}

function saveStore(store: AttachmentStore) {
  try { localStorage.setItem(LS_ATTACHMENTS, JSON.stringify(store)); } catch { /* quota */ }
}

export function attachmentsUsedBytes(store = loadStore()): number {
  let total = 0;
  for (const p of Object.values(store)) total += Math.ceil((p.b64.length * 3) / 4);
  return total;
}

function toBase64(bytes: Uint8Array): string {
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

export function decodeBase64(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Deterministic id from content + name — same file attached twice maps to
 *  one payload (dedupe by design), matching the project's stable-id rule. */
function attachmentId(name: string, bytes: Uint8Array): string {
  const content = crc32(bytes).toString(16).padStart(8, "0");
  const label = crc32(new TextEncoder().encode(name)).toString(16).padStart(8, "0");
  return `att-${content}-${label}`;
}

export interface AddResult {
  added: EntryAttachment[];
  errors: string[];
}

export async function addAttachmentFiles(files: File[]): Promise<AddResult> {
  const added: EntryAttachment[] = [];
  const errors: string[] = [];
  const store = loadStore();
  let budget = MAX_TOTAL_BYTES - attachmentsUsedBytes(store);
  for (const f of files) {
    if (f.size > MAX_FILE_BYTES) {
      errors.push(`${f.name}: ${f.size} bytes exceeds the ${MAX_FILE_BYTES / 1024} KB per-file cap`);
      continue;
    }
    if (f.size > budget) {
      errors.push(`${f.name}: local storage budget exhausted (${Math.max(0, budget)} bytes left)`);
      continue;
    }
    const bytes = new Uint8Array(await f.arrayBuffer());
    const id = attachmentId(f.name, bytes);
    if (!(id in store)) {
      store[id] = { mime: f.type || "application/octet-stream", b64: toBase64(bytes) };
      saveStore(store);
    }
    budget -= f.size;
    added.push({ id, name: f.name, mime: store[id].mime, size: f.size, addedAt: new Date().toISOString() });
  }
  return { added, errors };
}

export function hasAttachmentPayload(id: string): boolean {
  return id in loadStore();
}

export function decodeAttachment(id: string): Uint8Array<ArrayBuffer> | null {
  const p = loadStore()[id];
  if (!p) return null;
  return decodeBase64(p.b64);
}

/** Download (or preview) an attachment by materializing a Blob URL.
 *  Returns null when the payload is missing — callers must surface that,
 *  never fabricate a file. */
export function attachmentObjectUrl(id: string): string | null {
  const cached = urlCache.get(id);
  if (cached) return cached;
  const bytes = decodeAttachment(id);
  if (!bytes) return null;
  const mime = loadStore()[id]?.mime ?? "application/octet-stream";
  const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
  urlCache.set(id, url);
  return url;
}

export function triggerAttachmentDownload(att: EntryAttachment): boolean {
  const url = attachmentObjectUrl(att.id);
  if (!url) return false;
  const a = document.createElement("a");
  a.href = url;
  a.download = att.name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  return true;
}

export function removeAttachmentPayloads(ids: string[]) {
  if (!ids.length) return;
  const store = loadStore();
  // Only delete payloads nothing else references (same-content dedupe).
  const stillReferenced = new Set<string>();
  try {
    const raw = localStorage.getItem("ba.cases.v2");
    if (raw) {
      for (const match of raw.matchAll(/att-[0-9a-f]{8}-[0-9a-f]{8}/g)) stillReferenced.add(match[0]);
    }
  } catch { /* keep payloads on read failure */ }
  for (const id of ids) {
    if (stillReferenced.has(id)) continue;
    delete store[id];
    const url = urlCache.get(id);
    if (url) { URL.revokeObjectURL(url); urlCache.delete(id); }
  }
  saveStore(store);
}

export function entryAttachments(e: Entry): EntryAttachment[] {
  return e.attachments ?? [];
}

export function caseAttachmentCount(c: Case): number {
  return c.entries.reduce((n, e) => n + entryAttachments(e).length, 0);
}
