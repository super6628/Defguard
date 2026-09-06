import { describe, expect, it } from 'vitest';
import {
  ActivityLogEventType,
  ActivityLogModule,
} from '../src/shared/api/activity-log-types';
import type { SiemActivityLogEvent } from '../src/pages/SiemPage/siem-classification';
import { buildSiemCsv } from '../src/pages/SiemPage/siem-export';
import { parseSiemNotes, updateSiemNote } from '../src/pages/SiemPage/siem-notes';

const event: SiemActivityLogEvent = {
  id: 42,
  timestamp: '2026-09-06T12:00:00Z',
  user_id: 7,
  username: 'analyst',
  ip: '192.0.2.42',
  location: 'HQ, Chicago',
  event: ActivityLogEventType.UserLoginFailed,
  module: ActivityLogModule.Defguard,
  device: 'browser',
  description: 'Failed login, repeated twice',
};

describe('SIEM CSV export', () => {
  it('includes classification metadata and escapes CSV values', () => {
    const csv = buildSiemCsv([event]);

    expect(csv).toContain('severity,detections,event');
    expect(csv).toContain('high,authentication-failures,user_login_failed');
    expect(csv).toContain('"HQ, Chicago"');
    expect(csv).toContain('"Failed login, repeated twice"');
  });
});

describe('SIEM investigation notes', () => {
  it('parses only non-empty string notes', () => {
    expect(parseSiemNotes('{"42":"reviewed","43":"   ","44":5}')).toEqual({
      '42': 'reviewed',
    });
  });

  it('adds, trims, and removes event notes immutably', () => {
    const added = updateSiemNote({}, 42, '  escalate to IAM  ');
    expect(added).toEqual({ '42': 'escalate to IAM' });
    expect(updateSiemNote(added, 42, '   ')).toEqual({});
  });
});
