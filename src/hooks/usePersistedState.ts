import { useEffect, useState } from "react";

export function usePersistedState<T>(key: string, initialValue: T, legacyKeys: readonly string[] = []) {
  const [value, setValue] = useState<T>(() => {
    try {
      for (const candidate of [key, ...legacyKeys]) {
        const saved = localStorage.getItem(candidate);
        if (saved) return JSON.parse(saved) as T;
      }
      return initialValue;
    } catch {
      return initialValue;
    }
  });

  useEffect(() => {
    localStorage.setItem(key, JSON.stringify(value));
  }, [key, value]);

  return [value, setValue] as const;
}
