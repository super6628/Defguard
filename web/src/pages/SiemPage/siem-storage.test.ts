import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  getSiemScopedStorageKey,
  readSiemScopedStorage,
  writeSiemScopedStorage,
} from './siem-storage';

describe('SIEM scoped browser storage', () => {
  afterEach(() => {
    window.localStorage.clear();
    vi.restoreAllMocks();
  });

  it('scopes keys by encoded username', () => {
    expect(getSiemScopedStorageKey('defguard.siem.notes.v1', 'admin+soc@example.com')).toBe(
      'defguard.siem.notes.v1.admin%2Bsoc%40example.com',
    );
  });

  it('does not create an unscoped key when the user is unavailable', () => {
    expect(getSiemScopedStorageKey('defguard.siem.notes.v1')).toBeNull();
    writeSiemScopedStorage('defguard.siem.notes.v1', undefined, '{"42":"note"}');
    expect(window.localStorage.length).toBe(0);
  });

  it('keeps analyst storage namespaces isolated', () => {
    writeSiemScopedStorage('defguard.siem.alerts.v1', 'alice', '{"42":"acknowledged"}');
    writeSiemScopedStorage('defguard.siem.alerts.v1', 'bob', '{"43":"acknowledged"}');

    expect(readSiemScopedStorage('defguard.siem.alerts.v1', 'alice')).toBe(
      '{"42":"acknowledged"}',
    );
    expect(readSiemScopedStorage('defguard.siem.alerts.v1', 'bob')).toBe(
      '{"43":"acknowledged"}',
    );
  });

  it('tolerates unavailable localStorage', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });

    expect(readSiemScopedStorage('defguard.siem.notes.v1', 'alice')).toBeNull();
    expect(() =>
      writeSiemScopedStorage('defguard.siem.notes.v1', 'alice', '{"42":"note"}'),
    ).not.toThrow();
  });
});
