import { useEffect, useState } from 'react';
import {
  SIEM_NOTES_STORAGE_KEY,
  parseSiemNotes,
  updateSiemNote,
  type SiemInvestigationNotes,
} from './siem-notes';

const loadNotes = (): SiemInvestigationNotes => {
  if (typeof window === 'undefined') return {};
  return parseSiemNotes(window.localStorage.getItem(SIEM_NOTES_STORAGE_KEY));
};

export const useSiemInvestigationNotes = () => {
  const [notes, setNotes] = useState<SiemInvestigationNotes>(loadNotes);

  useEffect(() => {
    try {
      window.localStorage.setItem(SIEM_NOTES_STORAGE_KEY, JSON.stringify(notes));
    } catch {
      // Local persistence is optional.
    }
  }, [notes]);

  const setEventNote = (eventId: number, note: string) => {
    setNotes((current) => updateSiemNote(current, eventId, note));
  };

  const getEventNote = (eventId: number) => notes[String(eventId)] ?? '';

  return { notes, getEventNote, setEventNote };
};
