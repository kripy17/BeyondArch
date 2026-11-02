import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as workspace from "@/lib/workspace-state";

export function useWorkspaceState(ws: workspace.WorkspaceId) {
  const [pending, setPending] = useState<workspace.WorkspaceState | null>(() => workspace.load(ws));
  const pendingRef = useRef(pending);
  pendingRef.current = pending;

  const accept = useCallback(() => {
    const s = pendingRef.current;
    setPending(null);
    return s;
  }, []);

  const save = useCallback(
    (state: { artifact: string; analysis?: unknown }) => {
      workspace.save(ws, state);
      setPending(null);
    },
    [ws],
  );

  const clear = useCallback(() => {
    workspace.clear(ws);
    setPending(null);
  }, [ws]);

  return useMemo(() => ({ pending, accept, save, clear }), [pending, accept, save, clear]);
}

export function useDebouncedWorkspaceSave(ws: workspace.WorkspaceId, artifact: string, delay = 1200) {
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!artifact.trim()) return;
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => workspace.save(ws, { artifact }), delay);
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [ws, artifact, delay]);
}
