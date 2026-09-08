type Props = {
  title: string;
  description?: string;
  actionLabel?: string;
  onAction?: () => void;
};

export const SiemStatePanel = ({ title, description, actionLabel, onAction }: Props) => (
  <div className="siem-state" role="status" aria-live="polite">
    <strong>{title}</strong>
    {description && <p>{description}</p>}
    {actionLabel && onAction && (
      <button className="siem-refresh" type="button" onClick={onAction}>
        {actionLabel}
      </button>
    )}
  </div>
);
