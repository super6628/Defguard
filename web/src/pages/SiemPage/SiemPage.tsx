import { useQuery } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import {
  activityLogEventDisplay,
  type ActivityLogEventTypeValue,
} from '../../shared/api/activity-log-types';
import api from '../../shared/api/api';
import type { ActivityLogEvent, ActivityLogSortKey } from '../../shared/api/types';
import { Page } from '../../shared/components/Page/Page';
import { displayDate } from '../../shared/utils/displayDate';
import './style.scss';

type Severity = 'critical' | 'high' | 'medium' | 'low';

const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low'];

const criticalEvents = new Set<ActivityLogEventTypeValue>([
  'recovery_code_used',
  'mfa_disabled',
  'user_mfa_disabled',
  'gateway_deleted',
  'proxy_deleted',
]);

const highEvents = new Set<ActivityLogEventTypeValue>([
  'user_login_failed',
  'user_mfa_login_failed',
  'vpn_client_mfa_failed',
  'device_posture_check_failed',
  'password_changed_by_admin',
  'password_reset',
  'user_removed',
  'device_removed',
  'network_device_removed',
]);

const mediumEvents = new Set<ActivityLogEventTypeValue>([
  'settings_updated',
  'settings_updated_partial',
  'enterprise_settings_updated',
  'api_token_added',
  'authentication_key_added',
  'group_modified',
  'user_groups_modified',
  'gateway_disconnected',
  'proxy_disconnected',
]);

const getSeverity = (event: ActivityLogEventTypeValue): Severity => {
  if (criticalEvents.has(event)) return 'critical';
  if (highEvents.has(event)) return 'high';
  if (mediumEvents.has(event)) return 'medium';
  return 'low';
};

const formatEvent = (event: ActivityLogEventTypeValue) =>
  activityLogEventDisplay[event] ?? event.replaceAll('_', ' ');

export const SiemPage = () => {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState<Severity | 'all'>('all');
  const [source, setSource] = useState('all');

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['siem', 'activity-log'],
    queryFn: () =>
      api.getActivityLog({
        page: 1,
        sort_by: 'timestamp' as ActivityLogSortKey,
        sort_order: 'desc',
      }),
    refetchInterval: 30_000,
  });

  const events = data?.data ?? [];
  const sources = useMemo(
    () => Array.from(new Set(events.map((event) => event.module))).sort(),
    [events],
  );

  const filteredEvents = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();

    return events.filter((event) => {
      const eventSeverity = getSeverity(event.event);
      const matchesSeverity = severity === 'all' || eventSeverity === severity;
      const matchesSource = source === 'all' || event.module === source;
      const matchesQuery =
        normalizedQuery.length === 0 ||
        [
          event.username,
          event.ip,
          event.location,
          event.description,
          event.module,
          formatEvent(event.event),
        ]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(normalizedQuery));

      return matchesSeverity && matchesSource && matchesQuery;
    });
  }, [events, query, severity, source]);

  const severityCounts = useMemo(
    () =>
      events.reduce<Record<Severity, number>>(
        (acc, event) => {
          acc[getSeverity(event.event)] += 1;
          return acc;
        },
        { critical: 0, high: 0, medium: 0, low: 0 },
      ),
    [events],
  );

  const activeSources = new Set(events.map((event) => event.module)).size;

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
            <span>Events loaded</span>
            <strong>{events.length}</strong>
            <small>Latest Activity Log page</small>
          </article>
          <article className="siem-kpi">
            <span>Critical</span>
            <strong>{severityCounts.critical}</strong>
            <small>Derived severity</small>
          </article>
          <article className="siem-kpi">
            <span>High</span>
            <strong>{severityCounts.high}</strong>
            <small>Needs investigation</small>
          </article>
          <article className="siem-kpi">
            <span>Active sources</span>
            <strong>{activeSources}</strong>
            <small>Defguard modules</small>
          </article>
        </section>

        <section className="siem-panel">
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
              <span>Search</span>
              <input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="User, IP, event, description…"
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
              <span>Source</span>
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
                    <th>Severity</th>
                    <th>Time</th>
                    <th>Event</th>
                    <th>Actor</th>
                    <th>Source</th>
                    <th>IP / Location</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.map((event: ActivityLogEvent) => {
                    const eventSeverity = getSeverity(event.event);
                    const networkContext = [event.ip, event.location].filter(Boolean).join(' · ');
                    return (
                      <tr key={event.id}>
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
                        <td className="siem-description">{event.description || '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="siem-footnote">
          <strong>Severity is currently derived in the UI.</strong>
          <span>
            This first SIEM surface uses the existing Defguard Activity Log as its live source;
            server-side detection rules and additional collectors can be connected next.
          </span>
        </section>
      </div>
    </Page>
  );
};
