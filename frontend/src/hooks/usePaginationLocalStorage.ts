import { useState, useCallback, useRef, useEffect } from "react";

type Dict = Record<string, unknown>;

function getFromStorage<T extends Dict>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function setToStorage(key: string, value: Dict): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {}
}

function readUrlParams(): Dict {
  if (typeof window === "undefined") return {};
  const params = new URLSearchParams(window.location.search);
  const out: Dict = {};
  for (const [k, v] of params) {
    try {
      out[k] = JSON.parse(v);
    } catch {
      out[k] = v;
    }
  }
  return out;
}

function writeUrlParams(patch: Dict): void {
  if (typeof window === "undefined") return;
  const url = new URL(window.location.href);
  for (const [k, v] of Object.entries(patch)) {
    if (v === undefined || v === null) {
      url.searchParams.delete(k);
    } else if (typeof v === "string") {
      url.searchParams.set(k, v);
    } else {
      url.searchParams.set(k, JSON.stringify(v));
    }
  }
  window.history.replaceState(null, "", url.toString());
}

export function usePaginationLocalStorage<T extends Dict>(
  storageKey: string,
  defaults: T,
) {
  const [state, setState] = useState<T>(() => {
    const url = readUrlParams();
    const storage = getFromStorage(storageKey, defaults);
    return { ...defaults, ...storage, ...url } as T;
  });

  const stateRef = useRef(state);
  stateRef.current = state;

  const defaultsRef = useRef(defaults);
  defaultsRef.current = defaults;

  useEffect(() => {
    const handler = (e: StorageEvent) => {
      if (e.key === storageKey) {
        const fresh = getFromStorage(storageKey, defaultsRef.current);
        setState((prev) => ({ ...prev, ...fresh }));
      }
    };
    window.addEventListener("storage", handler);
    return () => window.removeEventListener("storage", handler);
  }, [storageKey]);

  const setValue = useCallback(
    (patch: Partial<T> | ((prev: T) => Partial<T>)) => {
      setState((prev) => {
        const resolved = typeof patch === "function" ? patch(prev) : patch;
        const next = { ...prev, ...resolved } as T;
        setToStorage(storageKey, next);
        writeUrlParams(resolved as Dict);
        return next;
      });
    },
    [storageKey],
  );

  const reset = useCallback(() => {
    setToStorage(storageKey, defaultsRef.current);
    writeUrlParams({});
    setState(defaultsRef.current);
  }, [storageKey]);

  return [state, setValue, reset] as const;
}
