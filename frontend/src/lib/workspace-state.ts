import { storageGet, storageSet } from "@/lib/storage";

export const WORKSPACE_STATE_KEY = "ba.workspace.v1";
export const WORKSPACE_TTL_MS = 24 * 60 * 60 * 1000;

export type WorkspaceId = "url" | "file" | "phishing" | "parser" | "logs" | "pcap";

export interface WorkspaceState {
  artifact: string;
  analysis?: unknown;
  updatedAt: number;
}

export function expired(updatedAt: number, now = Date.now()): boolean {
  return now - updatedAt > WORKSPACE_TTL_MS;
}

export function save(ws: WorkspaceId, state: Omit<WorkspaceState, "updatedAt">): void {
  const all = storageGet<Partial<Record<WorkspaceId, WorkspaceState>>>(WORKSPACE_STATE_KEY, {});
  all[ws] = { ...state, updatedAt: Date.now() };
  storageSet(WORKSPACE_STATE_KEY, all);
}

export function load(ws: WorkspaceId): WorkspaceState | null {
  const all = storageGet<Partial<Record<WorkspaceId, WorkspaceState>>>(WORKSPACE_STATE_KEY, {});
  const s = all[ws];
  if (!s || typeof s.artifact !== "string" || expired(s.updatedAt)) return null;
  return s;
}

export function clear(ws: WorkspaceId): void {
  const all = storageGet<Partial<Record<WorkspaceId, WorkspaceState>>>(WORKSPACE_STATE_KEY, {});
  delete all[ws];
  storageSet(WORKSPACE_STATE_KEY, all);
}

export function listActive(): Array<{ ws: WorkspaceId; state: WorkspaceState }> {
  const all = storageGet<Partial<Record<WorkspaceId, WorkspaceState>>>(WORKSPACE_STATE_KEY, {});
  return (Object.entries(all) as [WorkspaceId, WorkspaceState][])
    .filter(([, s]) => s && typeof s.artifact === "string" && !expired(s.updatedAt))
    .sort((a, b) => b[1].updatedAt - a[1].updatedAt)
    .map(([ws, state]) => ({ ws, state }));
}

export function lastActive(): { ws: WorkspaceId; state: WorkspaceState } | null {
  return listActive()[0] ?? null;
}
