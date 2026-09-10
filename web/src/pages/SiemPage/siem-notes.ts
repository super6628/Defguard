export type SiemInvestigationNotes = Record<string, string>;

export const SIEM_NOTES_STORAGE_KEY = 'defguard.siem.notes.v1';
export const MAX_SIEM_NOTE_CHARS = 4096;
export const MAX_SIEM_NOTES = 1000;

const isValidEventId = (key: string) => /^\d+$/.test(key) && Number(key) > 0;

const boundNotes = (entries: Array<[string, string]>): SiemInvestigationNotes =>
  Object.fromEntries(entries.slice(-MAX_SIEM_NOTES));

export const parseSiemNotes = (value: string | null): SiemInvestigationNotes => {
  if (!value) return {};

  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    const validEntries = Object.entries(parsed).flatMap(([key, note]) => {
      if (!isValidEventId(key) || typeof note !== 'string') return [];
      const trimmed = note.trim();
      if (!trimmed) return [];
      return [[key, trimmed.slice(0, MAX_SIEM_NOTE_CHARS)] as [string, string]];
    });
    return boundNotes(validEntries);
  } catch {
    return {};
  }
};

export const updateSiemNote = (
  notes: SiemInvestigationNotes,
  eventId: number,
  note: string,
): SiemInvestigationNotes => {
  if (!Number.isSafeInteger(eventId) || eventId <= 0) return notes;

  const key = String(eventId);
  const trimmed = note.trim();

  if (!trimmed) {
    const remaining = { ...notes };
    delete remaining[key];
    return remaining;
  }

  // Reinsert the key at the end so the bounded map retains the most recently edited notes.
  const entries = Object.entries(notes).filter(([existingKey]) => existingKey !== key);
  entries.push([key, trimmed.slice(0, MAX_SIEM_NOTE_CHARS)]);
  return boundNotes(entries);
};
