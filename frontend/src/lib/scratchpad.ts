/**
 * Analyst scratch notes (personal workspace). One flat list of short
 * freeform notes stored locally — never synced, never uploaded. Kept
 * deliberately dumb: id, text, timestamp. Ordering is newest-first.
 */

const SCRATCH_KEY = "ba.scratch.v1";
export const SCRATCH_LIMIT = 200;

export type ScratchNote = {
  id: string;
  ts: string;
  text: string;
};

function isValid(v: unknown): v is ScratchNote {
  if (!v || typeof v !== "object") return false;
  const n = v as Partial<ScratchNote>;
  return typeof n.id === "string" && typeof n.ts === "string" && typeof n.text === "string";
}

export function loadScratchNotes(): ScratchNote[] {
  try {
    const raw = localStorage.getItem(SCRATCH_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : [];
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isValid).slice(0, SCRATCH_LIMIT);
  } catch {
    return [];
  }
}

function saveNotes(notes: ScratchNote[]) {
  try { localStorage.setItem(SCRATCH_KEY, JSON.stringify(notes.slice(0, SCRATCH_LIMIT))); } catch { /* best-effort */ }
}

/** Append a note; returns the new list (newest first). Empty text is ignored. */
export function addScratchNote(text: string): ScratchNote[] {
  const trimmed = text.trim();
  if (!trimmed) return loadScratchNotes();
  const note: ScratchNote = { id: `sn-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`, ts: new Date().toISOString(), text: trimmed };
  const next = [note, ...loadScratchNotes()].slice(0, SCRATCH_LIMIT);
  saveNotes(next);
  return next;
}

export function deleteScratchNote(id: string): ScratchNote[] {
  const next = loadScratchNotes().filter((n) => n.id !== id);
  saveNotes(next);
  return next;
}
