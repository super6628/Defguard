import type {
  ActivityLogEventTypeValue,
} from '../../shared/api/activity-log-types';
import type { ActivityLogEvent } from '../../shared/api/types';
import type {
  SiemDetectionRuleId,
  SiemSeverity,
} from '../../shared/api/siem-types';

export type SiemActivityLogEvent = ActivityLogEvent & {
  siem_severity?: SiemSeverity;
  siem_detections?: SiemDetectionRuleId[];
};

export type SiemRuleDefinition = {
  id: SiemDetectionRuleId;
  label: string;
  description: string;
  severity: SiemSeverity;
};

export const SIEM_RULE_DEFINITIONS: SiemRuleDefinition[] = [
  {
    id: 'authentication-failures',
    label: 'Authentication failures',
    description: 'Failed user, MFA, and VPN MFA authentication activity.',
    severity: 'high',
  },
  {
    id: 'credential-security-changes',
    label: 'Credential & MFA changes',
    description: 'Recovery, MFA disablement, password, API token, and auth-key changes.',
    severity: 'critical',
  },
  {
    id: 'posture-failures',
    label: 'Posture failures',
    description: 'Device posture checks that did not meet policy.',
    severity: 'high',
  },
  {
    id: 'infrastructure-changes',
    label: 'Infrastructure changes',
    description: 'Gateway, proxy, and security-sensitive settings activity.',
    severity: 'medium',
  },
];

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

const authenticationFailureEvents = new Set<ActivityLogEventTypeValue>([
  'user_login_failed',
  'user_mfa_login_failed',
  'vpn_client_mfa_failed',
]);

const credentialChangeEvents = new Set<ActivityLogEventTypeValue>([
  'recovery_code_used',
  'mfa_disabled',
  'user_mfa_disabled',
  'password_changed_by_admin',
  'password_reset',
  'api_token_added',
  'authentication_key_added',
]);

const infrastructureChangeEvents = new Set<ActivityLogEventTypeValue>([
  'gateway_deleted',
  'proxy_deleted',
  'gateway_disconnected',
  'proxy_disconnected',
  'settings_updated',
  'settings_updated_partial',
  'enterprise_settings_updated',
]);

export const getFallbackSeverity = (
  event: ActivityLogEventTypeValue,
): SiemSeverity => {
  if (criticalEvents.has(event)) return 'critical';
  if (highEvents.has(event)) return 'high';
  if (mediumEvents.has(event)) return 'medium';
  return 'low';
};

export const getFallbackDetections = (
  event: ActivityLogEventTypeValue,
): SiemDetectionRuleId[] => {
  const detections: SiemDetectionRuleId[] = [];

  if (authenticationFailureEvents.has(event)) {
    detections.push('authentication-failures');
  }
  if (credentialChangeEvents.has(event)) {
    detections.push('credential-security-changes');
  }
  if (event === 'device_posture_check_failed') {
    detections.push('posture-failures');
  }
  if (infrastructureChangeEvents.has(event)) {
    detections.push('infrastructure-changes');
  }

  return detections;
};

export const getSiemSeverity = (event: SiemActivityLogEvent): SiemSeverity =>
  event.siem_severity ?? getFallbackSeverity(event.event);

export const getSiemDetections = (
  event: SiemActivityLogEvent,
): SiemDetectionRuleId[] =>
  event.siem_detections ?? getFallbackDetections(event.event);

export const countSiemDetection = (
  events: SiemActivityLogEvent[],
  ruleId: SiemDetectionRuleId,
) =>
  events.reduce(
    (count, event) => count + Number(getSiemDetections(event).includes(ruleId)),
    0,
  );
