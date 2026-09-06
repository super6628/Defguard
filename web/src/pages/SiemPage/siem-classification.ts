import {
  ActivityLogEventType,
  type ActivityLogEventTypeValue,
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
    description: 'Recovery, MFA, password, API token, and authentication-key changes.',
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
    label: 'Security configuration changes',
    description: 'Gateway, proxy, posture, logging, identity, webhook, and network changes.',
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
  'mfa_totp_disabled',
  'mfa_email_disabled',
  'mfa_security_key_removed',
]);

const mediumEvents = new Set<ActivityLogEventTypeValue>([
  'settings_updated',
  'settings_updated_partial',
  'enterprise_settings_updated',
  'api_token_added',
  'api_token_removed',
  'api_token_renamed',
  'authentication_key_added',
  'authentication_key_removed',
  'authentication_key_renamed',
  'password_changed',
  'mfa_totp_enabled',
  'mfa_email_enabled',
  'mfa_security_key_added',
  'group_added',
  'group_modified',
  'group_removed',
  'group_member_added',
  'group_member_removed',
  'group_members_modified',
  'groups_bulk_assigned',
  'user_groups_modified',
  'activity_log_stream_created',
  'activity_log_stream_modified',
  'activity_log_stream_removed',
  'web_hook_added',
  'web_hook_modified',
  'web_hook_removed',
  'web_hook_state_changed',
  'open_id_app_added',
  'open_id_app_removed',
  'open_id_app_modified',
  'open_id_app_state_changed',
  'open_id_provider_removed',
  'open_id_provider_modified',
  'client_configuration_token_added',
  'vpn_location_added',
  'vpn_location_removed',
  'vpn_location_modified',
  'user_snat_binding_added',
  'user_snat_binding_modified',
  'user_snat_binding_removed',
  'gateway_modified',
  'gateway_disconnected',
  'proxy_modified',
  'proxy_disconnected',
  'device_posture_created',
  'device_posture_updated',
  'device_posture_deleted',
  'device_posture_duplicated',
  'device_posture_locations_assigned',
  'location_postures_assigned',
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
  'mfa_totp_enabled',
  'mfa_totp_disabled',
  'mfa_email_enabled',
  'mfa_email_disabled',
  'mfa_security_key_added',
  'mfa_security_key_removed',
  'password_changed',
  'password_changed_by_admin',
  'password_reset',
  'api_token_added',
  'api_token_removed',
  'api_token_renamed',
  'authentication_key_added',
  'authentication_key_removed',
  'authentication_key_renamed',
]);

const infrastructureChangeEvents = new Set<ActivityLogEventTypeValue>([
  'gateway_deleted',
  'gateway_modified',
  'proxy_deleted',
  'proxy_modified',
  'gateway_disconnected',
  'proxy_disconnected',
  'settings_updated',
  'settings_updated_partial',
  'enterprise_settings_updated',
  'group_added',
  'group_modified',
  'group_removed',
  'group_member_added',
  'group_member_removed',
  'group_members_modified',
  'groups_bulk_assigned',
  'user_groups_modified',
  'activity_log_stream_created',
  'activity_log_stream_modified',
  'activity_log_stream_removed',
  'web_hook_added',
  'web_hook_modified',
  'web_hook_removed',
  'web_hook_state_changed',
  'open_id_app_added',
  'open_id_app_removed',
  'open_id_app_modified',
  'open_id_app_state_changed',
  'open_id_provider_removed',
  'open_id_provider_modified',
  'client_configuration_token_added',
  'vpn_location_added',
  'vpn_location_removed',
  'vpn_location_modified',
  'user_snat_binding_added',
  'user_snat_binding_modified',
  'user_snat_binding_removed',
  'device_posture_created',
  'device_posture_updated',
  'device_posture_deleted',
  'device_posture_duplicated',
  'device_posture_locations_assigned',
  'location_postures_assigned',
]);

export const getFallbackSeverity = (
  event: ActivityLogEventTypeValue,
): SiemSeverity => {
  if (criticalEvents.has(event)) return 'critical';
  if (highEvents.has(event)) return 'high';
  if (mediumEvents.has(event)) return 'medium';
  return 'low';
};

export const getEventTypesForSeverity = (
  severity: SiemSeverity,
): ActivityLogEventTypeValue[] =>
  Object.values(ActivityLogEventType).filter(
    (event) => getFallbackSeverity(event) === severity,
  );

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
