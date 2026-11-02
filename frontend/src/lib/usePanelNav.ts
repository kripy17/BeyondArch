import { useState, useCallback, useEffect } from "react";

export type PanelNavAction = 
  | { key: "j" | "k"; label: "Next item" | "Previous item" }
  | { key: "y"; label: "Copy selected" }
  | { key: "e"; label: "Enrich selected IOC" }
  | { key: "c"; label: "Attach to case" }
  | { key: "."; label: "Context menu" };

export function usePanelNav<T>(items: T[], options?: {
  onCopy?: (item: T) => void;
  onEnrich?: (item: T) => void;
  onAttach?: (item: T) => void;
  onContext?: (item: T) => void;
}) {
  const [index, setIndex] = useState(0);

  useEffect(() => {
    if (index >= items.length) setIndex(Math.max(0, items.length - 1));
  }, [items.length, index]);

  const selected = items[index] ?? null;

  return { index, setIndex, selected };
}
