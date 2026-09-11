type Props = {
  title: string;
  description?: string;
  actionLabel?: string;
  onAction?: () => void;
  role?: 'status' | 'alert';
};

export const SiemStatePanel = ({
  title,
  description,
  actionLabel,
  onAction,
  role = 'status',
}: Props) => (
  <div
    className="siem-state"
    role={role}
    aria-live={role === 'alert' ? 'assertive' : 'polite'}
  >
    <strong>{title}</strong>
    {description && <p>{description}</p>}
    {actionLabel && onAction && (
      <button className="siem-refresh" type="button" onClick={onAction}>
        {actionLabel}
      </button>
    )}
  </div>
);
