export type SiemInvestigationNotes = Record<string, string>;

export const SIEM_NOTES_STORAGE_KEY = 'defguard.siem.notes.v1';
export const MAX_PERSISTED_SIEM_NOTES = 250;

const eventIdDescending = ([left]: [string, unknown], [right]: [string, unknown]) =>
  Number(right) - Number(left);

export const pruneSiemNotes = (
  notes: Record<string, unknown>,
): SiemInvestigationNotes =>
  Object.fromEntries(
    Object.entries(notes)
      .filter(
        ([eventId, note]) =>
          /^\d+$/.test(eventId) && typeof note === 'string' && note.trim().length > 0,
      )
      .sort(eventIdDescending)
      .slice(0, MAX_PERSISTED_SIEM_NOTES)
      .map(([eventId, note]) => [eventId, (note as string).trim()]),
  ) as SiemInvestigationNotes;

export const parseSiemNotes = (value: string | null): SiemInvestigationNotes => {
  if (!value) return {};

  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return pruneSiemNotes(parsed as Record<string, unknown>);
  } catch {
    return {};
  }
};

export const updateSiemNote = (
  notes: SiemInvestigationNotes,
  eventId: number,
  note: string,
): SiemInvestigationNotes => {
  const key = String(eventId);
  const trimmed = note.trim();

  if (!trimmed) {
    const remaining = { ...notes };
    delete remaining[key];
    return remaining;
  }

  return pruneSiemNotes({ ...notes, [key]: trimmed });
};
