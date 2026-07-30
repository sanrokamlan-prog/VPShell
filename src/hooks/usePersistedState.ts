import { useEffect, useState } from "react";

export function usePersistedState<T>(
  key: string,
  initialValue: T,
  legacyKeys: readonly string[] = [],
  migrate?: (value: T) => T,
) {
  const [value, setValue] = useState<T>(() => {
    try {
      for (const candidate of [key, ...legacyKeys]) {
        const saved = localStorage.getItem(candidate);
        if (saved) {
          const parsed = JSON.parse(saved) as T;
          return migrate ? migrate(parsed) : parsed;
        }
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
