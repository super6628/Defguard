export type SiemInvestigationNotes = Record<string, string>;

export const SIEM_NOTES_STORAGE_KEY = 'defguard.siem.notes.v1';

export const parseSiemNotes = (value: string | null): SiemInvestigationNotes => {
  if (!value) return {};

  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    return Object.fromEntries(
      Object.entries(parsed).filter(
        ([, note]) => typeof note === 'string' && note.trim().length > 0,
      ),
    ) as SiemInvestigationNotes;
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
    const { [key]: _removed, ...remaining } = notes;
    return remaining;
  }

  return { ...notes, [key]: trimmed };
};
