export type SiemAlertStatus = 'open' | 'acknowledged';
export type SiemAlertState = Record<string, SiemAlertStatus>;

export const MAX_PERSISTED_SIEM_ACKNOWLEDGEMENTS = 500;

const eventIdDescending = ([left]: [string, unknown], [right]: [string, unknown]) =>
  Number(right) - Number(left);

export const pruneSiemAlertState = (
  state: Record<string, unknown>,
): SiemAlertState =>
  Object.fromEntries(
    Object.entries(state)
      .filter(([eventId, status]) => /^\d+$/.test(eventId) && status === 'acknowledged')
      .sort(eventIdDescending)
      .slice(0, MAX_PERSISTED_SIEM_ACKNOWLEDGEMENTS),
  ) as SiemAlertState;

export const parseSiemAlertState = (value: string | null): SiemAlertState => {
  if (!value) return {};

  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return pruneSiemAlertState(parsed as Record<string, unknown>);
  } catch {
    return {};
  }
};

export const toggleSiemAlertState = (
  state: SiemAlertState,
  eventId: number,
): SiemAlertState => {
  const key = String(eventId);

  if (state[key] === 'acknowledged') {
    const next = { ...state };
    delete next[key];
    return next;
  }

  return pruneSiemAlertState({ ...state, [key]: 'acknowledged' });
};
