import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface AppStoreSnapshot {
  schemaVersion: number;
  revision: number;
  stateJson?: string;
  migratedLegacy: boolean;
  recoveryNote?: string;
}

interface SaveAppStateResult {
  revision: number;
  retainedEvents: number;
}

export interface PersistedStateStatus {
  ready: boolean;
  saving: boolean;
  error?: string;
  recoveryNote?: string;
}

interface LegacyState<T> {
  value: T;
  stateJson?: string;
}

function isDesktopRuntime() {
  return "__TAURI_INTERNALS__" in window;
}

function readLegacyState<T>(
  key: string,
  legacyKeys: readonly string[],
  initialValue: T,
  migrate?: (value: T) => T,
) {
  try {
    for (const candidate of [key, ...legacyKeys]) {
      const saved = localStorage.getItem(candidate);
      if (!saved) continue;
      const parsed = JSON.parse(saved) as T;
      const value = migrate ? migrate(parsed) : parsed;
      return { value, stateJson: JSON.stringify(value) };
    }
  } catch {
    // Rust will start with a clean database when the old WebView snapshot is invalid.
  }
  return { value: initialValue, stateJson: undefined };
}

export function usePersistedState<T>(
  key: string,
  initialValue: T,
  legacyKeys: readonly string[] = [],
  migrate?: (value: T) => T,
  cleanupKeys: readonly string[] = [],
) {
  const legacy = useRef<LegacyState<T> | null>(null);
  if (!legacy.current) legacy.current = readLegacyState(key, legacyKeys, initialValue, migrate);

  const [value, setValue] = useState<T>(legacy.current.value);
  const [status, setStatus] = useState<PersistedStateStatus>({
    ready: !isDesktopRuntime(),
    saving: false,
  });
  const revision = useRef(0);
  const ready = useRef(!isDesktopRuntime());
  const saveQueue = useRef(Promise.resolve());

  useEffect(() => {
    if (!isDesktopRuntime()) return;
    let disposed = false;
    void invoke<AppStoreSnapshot>("initialize_app_store", {
      request: { legacyStateJson: legacy.current?.stateJson ?? null },
    }).then((snapshot) => {
      if (disposed) return;
      let next = initialValue;
      if (snapshot.stateJson) {
        const parsed = JSON.parse(snapshot.stateJson) as T;
        next = migrate ? migrate(parsed) : parsed;
      }
      revision.current = snapshot.revision;
      ready.current = true;
      setValue(next);
      setStatus({ ready: true, saving: false, recoveryNote: snapshot.recoveryNote });
      try {
        for (const candidate of [key, ...legacyKeys, ...cleanupKeys]) localStorage.removeItem(candidate);
      } catch {
        // A blocked WebView storage API must not invalidate the completed SQLite migration.
      }
      legacy.current = { value: next, stateJson: undefined };
    }).catch((error) => {
      if (!disposed) {
        setStatus({ ready: false, saving: false, error: String(error) });
      }
    });
    return () => { disposed = true; };
  // The storage identity is fixed for the application lifetime.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!isDesktopRuntime() || !ready.current) return;
    const stateJson = JSON.stringify(value);
    const timer = window.setTimeout(() => {
      setStatus((current) => ({ ...current, saving: true, error: undefined }));
      saveQueue.current = saveQueue.current
        .catch(() => undefined)
        .then(async () => {
          const result = await invoke<SaveAppStateResult>("save_app_state", {
            request: { stateJson, expectedRevision: revision.current },
          });
          revision.current = result.revision;
          setStatus((current) => ({ ...current, ready: true, saving: false, error: undefined }));
        })
        .catch((error) => {
          setStatus((current) => ({ ...current, saving: false, error: String(error) }));
        });
    }, 300);
    return () => window.clearTimeout(timer);
  }, [value]);

  return [value, setValue, status] as const;
}
