import { useQuery } from '@tanstack/react-query';
import { useEffect, useMemo, useState } from 'react';
import { activityLogEventDisplay } from '../../shared/api/activity-log-types';
import api from '../../shared/api/api';
import type { SiemDetectionRuleId, SiemSeverity } from '../../shared/api/siem-types';
import type { ActivityLogSortKey } from '../../shared/api/types';
import { Page } from '../../shared/components/Page/Page';
import { displayDate } from '../../shared/utils/displayDate';
import {
  SIEM_RULE_DEFINITIONS,
  countSiemDetection,
  getSiemDetections,
  getSiemSeverity,
  type SiemActivityLogEvent,
} from './siem-classification';
import './style.scss';

type Severity = SiemSeverity;
type DetectionRuleId = SiemDetectionRuleId;
type AlertStatus = 'open' | 'acknowledged';
type PersistedRuleState = Record<DetectionRuleId, boolean>;
type PersistedAlertState = Record<string, AlertStatus>;

type DetectionSummary = {
  id: DetectionRuleId;
  label: string;
  description: string;
  severity: Severity;
  count: number;
  enabled: boolean;
};

const PAGE_SIZE = 50;
const SEARCH_DEBOUNCE_MS = 350;
const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low'];
const SIEM_RULES_STORAGE_KEY = 'defguard.siem.rules.v1';
const SIEM_ALERTS_STORAGE_KEY = 'defguard.siem.alerts.v1';

const defaultRuleState: PersistedRuleState = {
  'authentication-failures': true,
  'credential-security-changes': true,
  'posture-failures': true,
  'infrastructure-changes': true,
};

const formatEvent = (event: SiemActivityLogEvent['event']) =>
  activityLogEventDisplay[event] ?? event.replaceAll('_', ' ');

const loadRuleState = (): PersistedRuleState => {
  if (typeof window === 'undefined') return defaultRuleState;
  try {
    const stored = window.localStorage.getItem(SIEM_RULES_STORAGE_KEY);
    if (!stored) return defaultRuleState;
    const parsed = JSON.parse(stored) as Partial<Record<DetectionRuleId, unknown>>;
    return Object.fromEntries(
      Object.entries(defaultRuleState).map(([id, defaultValue]) => [
        id,
        typeof parsed[id as DetectionRuleId] === 'boolean'
          ? parsed[id as DetectionRuleId]
          : defaultValue,
      ]),
    ) as PersistedRuleState;
  } catch {
    return defaultRuleState;
  }
};

const loadAlertState = (): PersistedAlertState => {
  if (typeof window === 'undefined') return {};
  try {
    const stored = window.localStorage.getItem(SIEM_ALERTS_STORAGE_KEY);
    if (!stored) return {};
    const parsed = JSON.parse(stored) as Record<string, unknown>;
    return Object.fromEntries(
      Object.entries(parsed).filter(
        ([, status]) => status === 'open' || status === 'acknowledged',
      ),
    ) as PersistedAlertState;
  } catch {
    return {};
  }
};

export const SiemPage = () => {
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [severity, setSeverity] = useState<Severity | 'all'>('all');
  const [source, setSource] = useState('all');
  const [selectedEvent, setSelectedEvent] = useState<SiemActivityLogEvent | null>(null);
  const [ruleState, setRuleState] = useState<PersistedRuleState>(loadRuleState);
  const [alertState, setAlertState] = useState<PersistedAlertState>(loadAlertState);

  useEffect(() => {
    try {
      window.localStorage.setItem(SIEM_RULES_STORAGE_KEY, JSON.stringify(ruleState));
    } catch {
      // Local persistence is optional.
    }
  }, [ruleState]);

  useEffect(() => {
    try {
      window.localStorage.setItem(SIEM_ALERTS_STORAGE_KEY, JSON.stringify(alertState));
    } catch {
      // Local persistence is optional.
    }
  }, [alertState]);

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      setDebouncedQuery(query.trim());
      setPage(1);
    }, SEARCH_DEBOUNCE_MS);

    return () => window.clearTimeout(timeout);
  }, [query]);

  useEffect(() => {
    setSelectedEvent(null);
    setSource('all');
  }, [page, debouncedQuery]);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['siem', 'activity-log', page, debouncedQuery],
    queryFn: () =>
      api.getActivityLog({
        page,
        per_page: PAGE_SIZE,
        search: debouncedQuery || undefined,
        sort_by: 'timestamp' as ActivityLogSortKey,
        sort_order: 'desc',
      }),
    refetchInterval: 30_000,
  });

  const events = (data?.data ?? []) as SiemActivityLogEvent[];
  const pagination = data?.pagination;
  const totalPages = Math.max(pagination?.total_pages ?? 1, 1);
  const totalItems = pagination?.total_items ?? events.length;
  const currentPage = pagination?.current_page ?? page;

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const sources = useMemo(
    () => Array.from(new Set(events.map((event) => event.module))).sort(),
    [events],
  );

  const filteredEvents = useMemo(
    () =>
      events.filter((event) => {
        const matchesSeverity = severity === 'all' || getSiemSeverity(event) === severity;
        const matchesSource = source === 'all' || event.module === source;
        return matchesSeverity && matchesSource;
      }),
    [events, severity, source],
  );

  const severityCounts = useMemo(
    () =>
      events.reduce<Record<Severity, number>>(
        (acc, event) => {
          acc[getSiemSeverity(event)] += 1;
          return acc;
        },
        { critical: 0, high: 0, medium: 0, low: 0 },
      ),
    [events],
  );

  const detections = useMemo<DetectionSummary[]>(
    () =>
      SIEM_RULE_DEFINITIONS.map((definition) => ({
        ...definition,
        count: countSiemDetection(events, definition.id),
        enabled: ruleState[definition.id],
      })),
    [events, ruleState],
  );

  const activeSources = new Set(events.map((event) => event.module)).size;
  const activeAlertEvents = events.filter((event) =>
    getSiemDetections(event).some((ruleId) => ruleState[ruleId]),
  );
  const openAlerts = activeAlertEvents.filter(
    (event) => alertState[String(event.id)] !== 'acknowledged',
  ).length;
  const selectedSeverity = selectedEvent ? getSiemSeverity(selectedEvent) : null;
  const selectedAlertStatus = selectedEvent
    ? alertState[String(selectedEvent.id)] ?? 'open'
    : null;

  const toggleRule = (id: DetectionRuleId) => {
    setRuleState((current) => ({ ...current, [id]: !current[id] }));
  };

  const toggleAlertStatus = (eventId: number) => {
    const key = String(eventId);
    setAlertState((current) => ({
      ...current,
      [key]: current[key] === 'acknowledged' ? 'open' : 'acknowledged',
    }));
  };

  const changePage = (nextPage: number) => {
    if (nextPage < 1 || nextPage > totalPages || nextPage === page) return;
    setPage(nextPage);
  };

  return (
    <Page id="siem-page" title="SIEM">
      <div className="siem-page">
        <section className="siem-hero">
          <div>
            <p className="siem-eyebrow">Security information & event management</p>
            <h2>Security signal overview</h2>
            <p>
              Monitor Defguard security activity, prioritize risky events, and investigate
              authentication, VPN, posture, and administrative changes from one view.
            </p>
          </div>
          <div className="siem-live-status" aria-label="Activity log ingestion status">
            <span className="siem-status-dot" />
            Activity Log source
          </div>
        </section>

        <section className="siem-kpis" aria-label="SIEM summary">
          <article className="siem-kpi">
            <span>{debouncedQuery ? 'Matching events' : 'Total events'}</span>
            <strong>{totalItems}</strong>
            <small>{events.length} loaded on this page</small>
          </article>
          <article className="siem-kpi">
            <span>Open alerts</span>
            <strong>{openAlerts}</strong>
            <small>Current page, enabled detections</small>
          </article>
          <article className="siem-kpi">
            <span>Critical</span>
            <strong>{severityCounts.critical}</strong>
            <small>Current page, Core-classified</small>
          </article>
          <article className="siem-kpi">
            <span>Active sources</span>
            <strong>{activeSources}</strong>
            <small>Current page modules</small>
          </article>
        </section>

        <section className="siem-panel siem-detections-panel">
          <div className="siem-panel-header">
            <div>
              <p className="siem-eyebrow">Detection overview</p>
              <h3>Analyst signals</h3>
            </div>
            <span className="siem-panel-meta">Classification from Core; counts reflect this page</span>
          </div>
          <div className="siem-detections-grid">
            {detections.map((detection) => (
              <article
                className={`siem-detection-card${detection.enabled ? '' : ' siem-detection-disabled'}`}
                key={detection.id}
              >
                <div className="siem-detection-card-top">
                  <span className={`siem-severity siem-severity-${detection.severity}`}>
                    {detection.severity}
                  </span>
                  <strong>{detection.enabled ? detection.count : '—'}</strong>
                </div>
                <h4>{detection.label}</h4>
                <p>{detection.description}</p>
                <button
                  className="siem-rule-toggle"
                  type="button"
                  onClick={() => toggleRule(detection.id)}
                  aria-pressed={detection.enabled}
                >
                  {detection.enabled ? 'Enabled' : 'Paused'}
                </button>
              </article>
            ))}
          </div>
        </section>

        <section className="siem-workspace">
          <div className="siem-panel siem-events-panel">
            <div className="siem-panel-header">
              <div>
                <p className="siem-eyebrow">Detection queue</p>
                <h3>Security events</h3>
              </div>
              <button className="siem-refresh" type="button" onClick={() => void refetch()}>
                Refresh
              </button>
            </div>

            <div className="siem-filters">
              <label className="siem-search">
                <span>Search event history</span>
                <input
                  type="search"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="User, IP, device, event, description…"
                />
              </label>
              <label>
                <span>Severity</span>
                <select
                  value={severity}
                  onChange={(event) => setSeverity(event.target.value as Severity | 'all')}
                >
                  <option value="all">All severities</option>
                  {severityOrder.map((level) => (
                    <option key={level} value={level}>
                      {level[0].toUpperCase() + level.slice(1)}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                <span>Source on page</span>
                <select value={source} onChange={(event) => setSource(event.target.value)}>
                  <option value="all">All sources</option>
                  {sources.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            {isLoading && <div className="siem-state">Loading security events…</div>}
            {isError && (
              <div className="siem-state">
                Activity Log data could not be loaded. Use Refresh to retry.
              </div>
            )}
            {!isLoading && !isError && filteredEvents.length === 0 && (
              <div className="siem-state">No security events match the current filters.</div>
            )}

            {!isLoading && !isError && filteredEvents.length > 0 && (
              <div className="siem-table-wrap">
                <table className="siem-table">
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Severity</th>
                      <th>Time</th>
                      <th>Event</th>
                      <th>Actor</th>
                      <th>Source</th>
                      <th>IP / Location</th>
                      <th aria-label="Investigation action" />
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEvents.map((event) => {
                      const eventSeverity = getSiemSeverity(event);
                      const eventDetections = getSiemDetections(event);
                      const networkContext = [event.ip, event.location].filter(Boolean).join(' · ');
                      const isSelected = selectedEvent?.id === event.id;
                      const isAlert = eventDetections.some((ruleId) => ruleState[ruleId]);
                      const eventStatus = alertState[String(event.id)] ?? 'open';
                      return (
                        <tr
                          className={[
                            isSelected ? 'siem-row-selected' : '',
                            isAlert && eventStatus === 'acknowledged' ? 'siem-row-acknowledged' : '',
                          ]
                            .filter(Boolean)
                            .join(' ')}
                          key={event.id}
                        >
                          <td>
                            {isAlert ? (
                              <span className={`siem-alert-status siem-alert-${eventStatus}`}>
                                {eventStatus === 'acknowledged' ? 'Acknowledged' : 'Open'}
                              </span>
                            ) : (
                              <span className="siem-alert-status">Event</span>
                            )}
                          </td>
                          <td>
                            <span className={`siem-severity siem-severity-${eventSeverity}`}>
                              {eventSeverity}
                            </span>
                          </td>
                          <td className="siem-nowrap">
                            {displayDate(event.timestamp, 'DD/MM/YYYY HH:mm:ss')}
                          </td>
                          <td>{formatEvent(event.event)}</td>
                          <td>{event.username || 'System'}</td>
                          <td>{event.module}</td>
                          <td>{networkContext || '—'}</td>
                          <td className="siem-row-action">
                            <button
                              type="button"
                              onClick={() => setSelectedEvent(event)}
                              aria-label={`Investigate ${formatEvent(event.event)}`}
                            >
                              Investigate
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {!isLoading && !isError && totalPages > 1 && (
              <div className="siem-pagination" aria-label="Security event pagination">
                <button
                  className="siem-refresh"
                  type="button"
                  disabled={currentPage <= 1}
                  onClick={() => changePage(currentPage - 1)}
                >
                  Previous
                </button>
                <span className="siem-panel-meta">
                  Page {currentPage} of {totalPages} · {totalItems} events
                </span>
                <button
                  className="siem-refresh"
                  type="button"
                  disabled={currentPage >= totalPages}
                  onClick={() => changePage(currentPage + 1)}
                >
                  Next
                </button>
              </div>
            )}
          </div>

          <aside className="siem-panel siem-investigation" aria-label="Event investigation">
            <div className="siem-panel-header">
              <div>
                <p className="siem-eyebrow">Investigation</p>
                <h3>Event details</h3>
              </div>
              {selectedEvent && (
                <button
                  className="siem-close"
                  type="button"
                  onClick={() => setSelectedEvent(null)}
                  aria-label="Close investigation"
                >
                  Close
                </button>
              )}
            </div>

            {!selectedEvent && (
              <div className="siem-investigation-empty">
                <strong>Select a security event</strong>
                <p>Use Investigate in the event queue to inspect its full Activity Log context.</p>
              </div>
            )}

            {selectedEvent && selectedSeverity && selectedAlertStatus && (
              <div className="siem-investigation-body">
                <div className="siem-investigation-heading">
                  <div className="siem-investigation-badges">
                    <span className={`siem-severity siem-severity-${selectedSeverity}`}>
                      {selectedSeverity}
                    </span>
                    {getSiemDetections(selectedEvent).some((ruleId) => ruleState[ruleId]) && (
                      <span className={`siem-alert-status siem-alert-${selectedAlertStatus}`}>
                        {selectedAlertStatus === 'acknowledged' ? 'Acknowledged' : 'Open'}
                      </span>
                    )}
                  </div>
                  <h4>{formatEvent(selectedEvent.event)}</h4>
                  <p>{selectedEvent.description || 'No additional description was recorded.'}</p>
                  {getSiemDetections(selectedEvent).some((ruleId) => ruleState[ruleId]) && (
                    <button
                      className="siem-alert-action"
                      type="button"
                      onClick={() => toggleAlertStatus(selectedEvent.id)}
                    >
                      {selectedAlertStatus === 'acknowledged' ? 'Reopen alert' : 'Acknowledge alert'}
                    </button>
                  )}
                </div>

                <dl className="siem-event-details">
                  <div><dt>Timestamp</dt><dd>{displayDate(selectedEvent.timestamp, 'DD/MM/YYYY HH:mm:ss')}</dd></div>
                  <div><dt>Actor</dt><dd>{selectedEvent.username || 'System'}</dd></div>
                  <div><dt>User ID</dt><dd>{selectedEvent.user_id ?? '—'}</dd></div>
                  <div><dt>Module</dt><dd>{selectedEvent.module}</dd></div>
                  <div><dt>IP address</dt><dd>{selectedEvent.ip || '—'}</dd></div>
                  <div><dt>Location</dt><dd>{selectedEvent.location || '—'}</dd></div>
                  <div><dt>Device</dt><dd>{selectedEvent.device || '—'}</dd></div>
                  <div><dt>Event ID</dt><dd>{selectedEvent.id}</dd></div>
                </dl>
              </div>
            )}
          </aside>
        </section>

        <section className="siem-footnote">
          <strong>Core owns event classification; SIEM controls remain non-destructive.</strong>
          <span>
            Severity and detection metadata come from the Activity Log API when supported, with a
            compatibility fallback for older Core versions. Text search queries the full Activity
            Log history; severity and source filters remain page-local until Core exposes those
            SIEM-specific filters.
          </span>
        </section>
      </div>
    </Page>
  );
};
