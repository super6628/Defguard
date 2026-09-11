import { describe, expect, it } from 'vitest';
import {
  ActivityLogEventType,
  ActivityLogModule,
} from '../../shared/api/activity-log-types';
import type { SiemDetectionRuleId } from '../../shared/api/siem-types';
import {
  getFallbackDetections,
  getFallbackSeverity,
  getSiemDetections,
  getSiemSeverity,
  type SiemActivityLogEvent,
} from './siem-classification';

const allowedDetections = new Set<SiemDetectionRuleId>([
  'authentication-failures',
  'credential-security-changes',
  'posture-failures',
  'infrastructure-changes',
]);

const makeEvent = (
  event: SiemActivityLogEvent['event'],
): SiemActivityLogEvent => ({
  id: 1,
  timestamp: '2026-09-09T12:00:00Z',
  user_id: 1,
  username: 'analyst',
  ip: null,
  event,
  module: ActivityLogModule.Defguard,
  device: 'browser',
});

describe('SIEM classification contracts', () => {
  it('classifies every known Activity Log event with valid fallback metadata', () => {
    for (const event of Object.values(ActivityLogEventType)) {
      expect(['critical', 'high', 'medium', 'low']).toContain(getFallbackSeverity(event));
      const detections = getFallbackDetections(event);
      expect(detections.every((rule) => allowedDetections.has(rule))).toBe(true);
      expect(new Set(detections).size).toBe(detections.length);
    }
  });

  it('prefers Core-provided severity over frontend fallback classification', () => {
    const event = {
      ...makeEvent(ActivityLogEventType.UserLoginFailed),
      siem_severity: 'low' as const,
    };

    expect(getFallbackSeverity(event.event)).toBe('high');
    expect(getSiemSeverity(event)).toBe('low');
  });

  it('prefers Core-provided detections over frontend fallback detections', () => {
    const event = {
      ...makeEvent(ActivityLogEventType.UserLoginFailed),
      siem_detections: [] as SiemActivityLogEvent['siem_detections'],
    };

    expect(getFallbackDetections(event.event)).toContain('authentication-failures');
    expect(getSiemDetections(event)).toEqual([]);
  });
});
