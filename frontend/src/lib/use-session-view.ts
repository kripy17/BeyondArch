import { useCallback, useMemo, useRef, useState } from "react";
import { clearViewState, loadViewState, saveViewState } from "@/lib/session-view";

/** Persisted view state: value survives reloads under `key`, updates write
 * through immediately (view state is tiny; no debounce needed). */
export function useViewState<T>(key: string, initial: T): [T, (value: T | ((prev: T) => T)) => void, () => void] {
  const [value, setValue] = useState<T>(() => loadViewState<T>(key) ?? initial);
  const initialRef = useRef(initial);

  const set = useCallback(
    (next: T | ((prev: T) => T)) => {
      setValue((prev) => {
        const resolved = typeof next === "function" ? (next as (p: T) => T)(prev) : next;
        saveViewState(key, resolved);
        return resolved;
      });
    },
    [key],
  );

  const reset = useCallback(() => {
    clearViewState(key);
    setValue(initialRef.current);
  }, [key]);

  return useMemo(() => [value, set, reset], [value, set, reset]);
}
