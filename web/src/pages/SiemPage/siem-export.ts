import type { SiemActivityLogEvent } from './siem-classification';
import { getSiemDetections, getSiemSeverity } from './siem-classification';

const DANGEROUS_SPREADSHEET_PREFIX = /^[=+\-@]/;

const escapeCsvCell = (value: unknown) => {
  const rawText = value == null ? '' : String(value);
  const text = DANGEROUS_SPREADSHEET_PREFIX.test(rawText) ? `'${rawText}` : rawText;
  return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
};

export const buildSiemCsv = (events: SiemActivityLogEvent[]) => {
  const headers = [
    'id',
    'timestamp',
    'severity',
    'detections',
    'event',
    'username',
    'user_id',
    'module',
    'ip',
    'location',
    'device',
    'description',
  ];

  const rows = events.map((event) => [
    event.id,
    event.timestamp,
    getSiemSeverity(event),
    getSiemDetections(event).join(';'),
    event.event,
    event.username,
    event.user_id ?? '',
    event.module,
    event.ip ?? '',
    event.location ?? '',
    event.device,
    event.description ?? '',
  ]);

  return [headers, ...rows]
    .map((row) => row.map(escapeCsvCell).join(','))
    .join('\n');
};

export const downloadSiemCsv = (events: SiemActivityLogEvent[]) => {
  if (typeof document === 'undefined' || typeof URL === 'undefined') return;

  const blob = new Blob([buildSiemCsv(events)], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `defguard-siem-${new Date().toISOString().replaceAll(':', '-')}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
};
