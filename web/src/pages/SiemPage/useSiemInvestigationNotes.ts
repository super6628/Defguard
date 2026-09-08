import { useEffect, useState } from 'react';
import {
  SIEM_NOTES_STORAGE_KEY,
  parseSiemNotes,
  updateSiemNote,
  type SiemInvestigationNotes,
} from './siem-notes';
import { readSiemScopedStorage, writeSiemScopedStorage } from './siem-storage';

const loadNotes = (username?: string): SiemInvestigationNotes =>
  parseSiemNotes(readSiemScopedStorage(SIEM_NOTES_STORAGE_KEY, username));

export const useSiemInvestigationNotes = (username?: string) => {
  const [storageOwner, setStorageOwner] = useState(username);
  const [notes, setNotes] = useState<SiemInvestigationNotes>(() => loadNotes(username));

  useEffect(() => {
    if (storageOwner === username) return;
    setNotes(loadNotes(username));
    setStorageOwner(username);
  }, [storageOwner, username]);

  useEffect(() => {
    if (storageOwner !== username) return;
    writeSiemScopedStorage(SIEM_NOTES_STORAGE_KEY, username, JSON.stringify(notes));
  }, [notes, storageOwner, username]);

  const setEventNote = (eventId: number, note: string) => {
    setNotes((current) => updateSiemNote(current, eventId, note));
  };

  const getEventNote = (eventId: number) => notes[String(eventId)] ?? '';

  return { getEventNote, setEventNote };
};
