import { useEffect, useState } from 'react';

type Props = {
  eventId: number;
  initialNote: string;
  onSave: (note: string) => void;
};

export const SiemInvestigationNotes = ({ eventId, initialNote, onSave }: Props) => {
  const [draft, setDraft] = useState(initialNote);

  useEffect(() => {
    setDraft(initialNote);
  }, [eventId, initialNote]);

  const hasChanges = draft.trim() !== initialNote;

  return (
    <div className="siem-investigation-notes">
      <label htmlFor={`siem-note-${eventId}`}>Analyst notes</label>
      <textarea
        id={`siem-note-${eventId}`}
        value={draft}
        onChange={(event) => setDraft(event.target.value)}
        placeholder="Record triage context, follow-up, or escalation details…"
        rows={5}
      />
      <div className="siem-investigation-note-actions">
        <span>Stored in this browser only.</span>
        <button
          className="siem-alert-action"
          type="button"
          disabled={!hasChanges}
          onClick={() => onSave(draft)}
        >
          Save note
        </button>
      </div>
    </div>
  );
};
