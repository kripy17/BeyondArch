/**
 * Whole-workspace backup: every localStorage key under "ba." in one JSON
 * snapshot. Local-first means the browser profile IS the database — this is
 * its export/import path.
 */

export const BACKUP_FORMAT = "beyondlabs-workspace";
export const BACKUP_VERSION = 1;
const KEY_PREFIX = "ba.";

export type WorkspaceBackup = {
  format: typeof BACKUP_FORMAT;
  version: number;
  exportedAt: string;
  entries: { key: string; value: string }[];
};

export type ImportReport = {
  restored: string[];
  skippedForeign: string[];
};

export function collectWorkspace(): WorkspaceBackup {
  const entries: { key: string; value: string }[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (!key || !key.startsWith(KEY_PREFIX)) continue;
    const value = localStorage.getItem(key);
    if (value === null) continue;
    entries.push({ key, value });
  }
  return {
    format: BACKUP_FORMAT,
    version: BACKUP_VERSION,
    exportedAt: new Date().toISOString(),
    entries: entries.sort((a, b) => a.key.localeCompare(b.key)),
  };
}

export function serializeBackup(backup: WorkspaceBackup): string {
  return JSON.stringify(backup, null, 2);
}

/** Parses backup text honestly — throws on anything that isn't a BeyondLabs snapshot. */
export function parseBackup(text: string): WorkspaceBackup {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Not valid JSON");
  }
  const b = parsed as Partial<WorkspaceBackup> | null;
  if (!b || typeof b !== "object" || b.format !== BACKUP_FORMAT || typeof b.version !== "number") {
    throw new Error("Not a BeyondLabs workspace backup (missing format marker)");
  }
  if (!Array.isArray(b.entries)) throw new Error("Backup has no entries array");
  if (b.version > BACKUP_VERSION) throw new Error(`Backup version ${b.version} is newer than this app understands (${BACKUP_VERSION})`);
  return {
    format: BACKUP_FORMAT,
    version: b.version,
    exportedAt: typeof b.exportedAt === "string" ? b.exportedAt : "",
    entries: b.entries.filter((e) => e && typeof e.key === "string" && typeof e.value === "string"),
  };
}

/**
 * Restores a parsed snapshot. Keys outside "ba." are refused (never writes
 * foreign storage); current values are overwritten and reported.
 */
export function restoreBackup(backup: WorkspaceBackup): ImportReport {
  const report: ImportReport = { restored: [], skippedForeign: [] };
  for (const entry of backup.entries) {
    if (!entry.key.startsWith(KEY_PREFIX)) {
      report.skippedForeign.push(entry.key);
      continue;
    }
    try {
      localStorage.setItem(entry.key, entry.value);
      report.restored.push(entry.key);
    } catch {
      /* quota/private mode — skip honestly */
    }
  }
  try { window.dispatchEvent(new Event("search-index-invalidate")); } catch { /* non-window */ }
  return report;
}

export function backupFilename(backup: WorkspaceBackup): string {
  const day = backup.exportedAt.slice(0, 10) || new Date().toISOString().slice(0, 10);
  return `beyondlabs-workspace-${day}.json`;
}
