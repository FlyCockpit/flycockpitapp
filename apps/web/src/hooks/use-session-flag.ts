import { useCallback, useSyncExternalStore } from "react";

/**
 * Read a boolean flag from `sessionStorage` with `useSyncExternalStore` so the
 * component participates in React's concurrent rendering instead of relying on
 * `useEffect` to mirror external state into local state. Returns a `[flag,
 * setFlag]` pair.
 *
 * Why session storage:
 *   * Dismiss-once-per-tab semantics. Closing the tab or hitting refresh
 *     resets the flag, which matches what the "translated by" banner wants
 *     (don't pester the same user every navigation, do reset on reload).
 *   * Avoids the `useEffect(() => readLocalStorage(), [])` pattern banned by
 *     CLAUDE.md.
 *
 * SSR-safe: the snapshot returns the default value on the server where
 * `window` is undefined, and re-syncs on the client's first commit.
 */
export function useSessionFlag(
  key: string,
  defaultValue = false,
): [boolean, (next: boolean) => void] {
  const subscribe = useCallback(
    (onChange: () => void) => {
      if (typeof window === "undefined") return () => {};
      const handler = (event: StorageEvent) => {
        if (event.storageArea === window.sessionStorage && event.key === key) onChange();
      };
      window.addEventListener("storage", handler);
      return () => window.removeEventListener("storage", handler);
    },
    [key],
  );

  const getSnapshot = useCallback((): boolean => {
    if (typeof window === "undefined") return defaultValue;
    const raw = window.sessionStorage.getItem(key);
    if (raw === null) return defaultValue;
    return raw === "true";
  }, [key, defaultValue]);

  const getServerSnapshot = useCallback((): boolean => defaultValue, [defaultValue]);

  const value = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  const setFlag = useCallback(
    (next: boolean) => {
      if (typeof window === "undefined") return;
      window.sessionStorage.setItem(key, String(next));
      // `storage` events do not fire in the originating tab, so dispatch one
      // manually so subscribers in the same tab also see the change.
      window.dispatchEvent(
        new StorageEvent("storage", {
          key,
          newValue: String(next),
          storageArea: window.sessionStorage,
        }),
      );
    },
    [key],
  );

  return [value, setFlag];
}
