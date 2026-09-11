import { useEffect, useState } from 'react';

const MAX_NOTE_LENGTH = 2000;

type Props = {
  eventId: number;
  initialNote: string;
  onSave: (note: string) => void;
};

export const SiemInvestigationNotes = ({ eventId, initialNote, onSave }: Props) => {
  const [draft, setDraft] = useState(initialNote);

  // biome-ignore lint/correctness/useExhaustiveDependencies: eventId intentionally resets the draft when switching events that have the same saved note text.
  useEffect(() => {
    setDraft(initialNote);
  }, [eventId, initialNote]);

  const normalizedDraft = draft.trim();
  const hasChanges = normalizedDraft !== initialNote;
  const hasSavedNote = initialNote.length > 0;

  const saveNote = () => {
    onSave(normalizedDraft);
  };

  const clearNote = () => {
    setDraft('');
    onSave('');
  };

  return (
    <div className="siem-investigation-notes">
      <label htmlFor={`siem-note-${eventId}`}>Analyst notes</label>
      <textarea
        id={`siem-note-${eventId}`}
        value={draft}
        maxLength={MAX_NOTE_LENGTH}
        onChange={(event) => setDraft(event.target.value)}
        placeholder="Record triage context, follow-up, or escalation details…"
        rows={5}
      />
      <div className="siem-investigation-note-actions">
        <span>
          {draft.length}/{MAX_NOTE_LENGTH} characters · stored for this analyst in this
          browser.
        </span>
        <div>
          {hasSavedNote && (
            <button className="siem-alert-action" type="button" onClick={clearNote}>
              Clear note
            </button>
          )}
          <button
            className="siem-alert-action"
            type="button"
            disabled={!hasChanges}
            onClick={saveNote}
          >
            Save note
          </button>
        </div>
      </div>
    </div>
  );
};
