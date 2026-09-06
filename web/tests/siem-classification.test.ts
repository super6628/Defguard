import { describe, expect, it } from 'vitest';
import {
  ActivityLogEventType,
  ActivityLogModule,
} from '../src/shared/api/activity-log-types';
import {
  countSiemDetection,
  getEventTypesForSeverity,
  getFallbackDetections,
  getFallbackSeverity,
  getSiemDetections,
  getSiemSeverity,
  type SiemActivityLogEvent,
} from '../src/pages/SiemPage/siem-classification';

const event = (
  eventType: SiemActivityLogEvent['event'],
  overrides: Partial<SiemActivityLogEvent> = {},
): SiemActivityLogEvent => ({
  id: 1,
  timestamp: '2026-09-06T12:00:00Z',
  user_id: 1,
  username: 'analyst',
  ip: '192.0.2.1',
  event: eventType,
  module: ActivityLogModule.Defguard,
  device: 'browser',
  ...overrides,
});

describe('SIEM activity-log classification', () => {
  it('prioritizes server-owned severity over the compatibility fallback', () => {
    expect(
      getSiemSeverity(
        event(ActivityLogEventType.UserLogin, { siem_severity: 'critical' }),
      ),
    ).toBe('critical');
  });

  it('treats an explicit empty server detection list as authoritative', () => {
    expect(
      getSiemDetections(
        event(ActivityLogEventType.UserLoginFailed, { siem_detections: [] }),
      ),
    ).toEqual([]);
  });

  it('classifies representative security events by severity', () => {
    expect(getFallbackSeverity(ActivityLogEventType.MfaDisabled)).toBe('critical');
    expect(getFallbackSeverity(ActivityLogEventType.MfaTotpDisabled)).toBe('high');
    expect(getFallbackSeverity(ActivityLogEventType.ActivityLogStreamRemoved)).toBe('medium');
    expect(getFallbackSeverity(ActivityLogEventType.UserLogin)).toBe('low');
  });

  it('maps representative events to the expected detection families', () => {
    expect(getFallbackDetections(ActivityLogEventType.UserLoginFailed)).toEqual([
      'authentication-failures',
    ]);
    expect(getFallbackDetections(ActivityLogEventType.MfaSecurityKeyRemoved)).toEqual([
      'credential-security-changes',
    ]);
    expect(getFallbackDetections(ActivityLogEventType.DevicePostureCheckFailed)).toEqual([
      'posture-failures',
    ]);
    expect(getFallbackDetections(ActivityLogEventType.WebHookModified)).toEqual([
      'infrastructure-changes',
    ]);
  });

  it('partitions every known activity-log event into exactly one severity', () => {
    const allEvents = Object.values(ActivityLogEventType);
    const classified = ['critical', 'high', 'medium', 'low'].flatMap((severity) =>
      getEventTypesForSeverity(severity as 'critical' | 'high' | 'medium' | 'low'),
    );

    expect(classified).toHaveLength(allEvents.length);
    expect(new Set(classified).size).toBe(allEvents.length);
    expect(new Set(classified)).toEqual(new Set(allEvents));
  });

  it('counts detections using server metadata when present and fallback otherwise', () => {
    const events = [
      event(ActivityLogEventType.UserLoginFailed, { id: 1 }),
      event(ActivityLogEventType.UserLogin, {
        id: 2,
        siem_detections: ['authentication-failures'],
      }),
      event(ActivityLogEventType.UserLoginFailed, { id: 3, siem_detections: [] }),
    ];

    expect(countSiemDetection(events, 'authentication-failures')).toBe(2);
  });
});
