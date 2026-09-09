import { describe, expect, it } from 'vitest';
import {
  MAX_PERSISTED_SIEM_NOTES,
  parseSiemNotes,
  pruneSiemNotes,
  updateSiemNote,
} from './siem-notes';

describe('SIEM investigation notes', () => {
  it('rejects malformed persisted values', () => {
    expect(parseSiemNotes('[]')).toEqual({});
    expect(parseSiemNotes('null')).toEqual({});
    expect(parseSiemNotes('{not-json')).toEqual({});
  });

  it('keeps only valid numeric event IDs and non-empty notes', () => {
    expect(
      pruneSiemNotes({
        '10': '  investigate source IP  ',
        '11': '',
        invalid: 'discard me',
        '12': 42,
      }),
    ).toEqual({ '10': 'investigate source IP' });
  });

  it('bounds persisted notes to the newest event IDs', () => {
    const notes = Object.fromEntries(
      Array.from({ length: MAX_PERSISTED_SIEM_NOTES + 5 }, (_, index) => [
        String(index + 1),
        `note ${index + 1}`,
      ]),
    );

    const pruned = pruneSiemNotes(notes);

    expect(Object.keys(pruned)).toHaveLength(MAX_PERSISTED_SIEM_NOTES);
    expect(pruned[String(MAX_PERSISTED_SIEM_NOTES + 5)]).toBe(
      `note ${MAX_PERSISTED_SIEM_NOTES + 5}`,
    );
    expect(pruned['1']).toBeUndefined();
  });

  it('removes a note when the update is blank', () => {
    expect(updateSiemNote({ '25': 'saved' }, 25, '   ')).toEqual({});
  });
});
