import { describe, expect, it } from 'vitest';
import {
  MAX_PERSISTED_SIEM_ACKNOWLEDGEMENTS,
  parseSiemAlertState,
  pruneSiemAlertState,
  toggleSiemAlertState,
} from './siem-alert-state';

describe('SIEM alert state', () => {
  it('keeps only acknowledged numeric event IDs', () => {
    expect(
      pruneSiemAlertState({
        '42': 'acknowledged',
        '43': 'open',
        invalid: 'acknowledged',
        '44': 'other',
      }),
    ).toEqual({ '42': 'acknowledged' });
  });

  it('treats invalid persisted values as empty state', () => {
    expect(parseSiemAlertState(null)).toEqual({});
    expect(parseSiemAlertState('not-json')).toEqual({});
    expect(parseSiemAlertState('[]')).toEqual({});
  });

  it('removes an acknowledgement when an alert is reopened', () => {
    expect(toggleSiemAlertState({ '42': 'acknowledged' }, 42)).toEqual({});
  });

  it('adds an acknowledgement for an open alert', () => {
    expect(toggleSiemAlertState({}, 42)).toEqual({ '42': 'acknowledged' });
  });

  it('caps persisted acknowledgements to the newest event IDs', () => {
    const state = Object.fromEntries(
      Array.from({ length: MAX_PERSISTED_SIEM_ACKNOWLEDGEMENTS + 5 }, (_, index) => [
        String(index + 1),
        'acknowledged',
      ]),
    );

    const pruned = pruneSiemAlertState(state);

    expect(Object.keys(pruned)).toHaveLength(MAX_PERSISTED_SIEM_ACKNOWLEDGEMENTS);
    expect(pruned['1']).toBeUndefined();
    expect(pruned[String(MAX_PERSISTED_SIEM_ACKNOWLEDGEMENTS + 5)]).toBe('acknowledged');
  });
});
