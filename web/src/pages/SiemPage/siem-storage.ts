export const getSiemScopedStorageKey = (baseKey: string, username?: string) =>
  username ? `${baseKey}.${encodeURIComponent(username)}` : null;

export const readSiemScopedStorage = (baseKey: string, username?: string) => {
  const key = getSiemScopedStorageKey(baseKey, username);
  if (!key || typeof window === 'undefined') return null;

  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
};

export const writeSiemScopedStorage = (
  baseKey: string,
  username: string | undefined,
  value: string,
) => {
  const key = getSiemScopedStorageKey(baseKey, username);
  if (!key || typeof window === 'undefined') return;

  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Local persistence is optional.
  }
};
