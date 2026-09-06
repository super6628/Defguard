use std::fmt;

use axum::extract::State;
use axum_extra::extract::Query;
use chrono::{DateTime, NaiveDateTime, Utc};
use defguard_common::db::Id;
use ipnetwork::IpNetwork;
use sqlx::{FromRow, Postgres, QueryBuilder, Type};
use utoipa::ToSchema;

use super::{
    ApiErrorResponse,
    pagination::{PaginatedApiResponse, PaginatedApiResult, PaginationParams},
};
use crate::{appstate::AppState, auth::SessionInfo, db::models::activity_log::ActivityLogModule};

#[derive(Debug, Deserialize, Default)]
pub struct FilterParams {
    pub from: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    #[serde(default = "default_username")]
    pub username: Vec<String>,
    #[serde(default = "default_location")]
    pub location: Vec<String>,
    #[serde(default = "default_event")]
    pub event: Vec<String>,
    #[serde(default = "default_module")]
    pub module: Vec<ActivityLogModule>,
    pub search: Option<String>,
}

fn default_username() -> Vec<String> {
    Vec::new()
}

fn default_location() -> Vec<String> {
    Vec::new()
}

fn default_event() -> Vec<String> {
    Vec::new()
}

fn default_module() -> Vec<ActivityLogModule> {
    Vec::new()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct SortParams {
    #[serde(default)]
    pub sort_by: SortKey,
    #[serde(default)]
    pub sort_order: SortOrder,
}

#[derive(Debug, Deserialize, Type, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SortKey {
    #[default]
    Timestamp,
    Username,
    Location,
    Ip,
    Event,
    Module,
    Device,
}

impl fmt::Display for SortKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Timestamp => "timestamp",
            Self::Username => "username",
            Self::Location => "location",
            Self::Ip => "ip",
            Self::Event => "event",
            Self::Module => "module::text",
            Self::Device => "device",
        })
    }
}

#[derive(Debug, Deserialize, Serialize, Default, Type)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    Asc,
    #[default]
    Desc,
}

impl fmt::Display for SortOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        })
    }
}

/// Server-owned SIEM severity assigned to an activity log event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SiemSeverity {
    Critical,
    High,
    Medium,
    #[default]
    Low,
}

/// Server-owned SIEM detection families matching an activity log event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SiemDetectionRuleId {
    AuthenticationFailures,
    CredentialSecurityChanges,
    PostureFailures,
    InfrastructureChanges,
}

/// Activity log event as returned by the API.
#[derive(Serialize, FromRow, ToSchema)]
pub struct ApiActivityLogEvent {
    pub id: Id,
    pub timestamp: NaiveDateTime,
    pub user_id: Option<Id>,
    pub username: String,
    pub location: Option<String>,
    #[schema(value_type = Option<String>)]
    pub ip: Option<IpNetwork>,
    pub event: String,
    pub module: ActivityLogModule,
    pub device: String,
    pub description: Option<String>,
    /// SIEM severity derived by Core from the event type.
    #[sqlx(skip)]
    pub siem_severity: SiemSeverity,
    /// SIEM detection families matched by Core for the event type.
    #[sqlx(skip)]
    pub siem_detections: Vec<SiemDetectionRuleId>,
}

impl ApiActivityLogEvent {
    fn apply_siem_classification(&mut self) {
        let (severity, detections) = classify_siem_event(&self.event);
        self.siem_severity = severity;
        self.siem_detections = detections;
    }
}

fn classify_siem_event(event: &str) -> (SiemSeverity, Vec<SiemDetectionRuleId>) {
    let severity = match event {
        "recovery_code_used"
        | "mfa_disabled"
        | "user_mfa_disabled"
        | "gateway_deleted"
        | "proxy_deleted" => SiemSeverity::Critical,
        "user_login_failed"
        | "user_mfa_login_failed"
        | "vpn_client_mfa_failed"
        | "device_posture_check_failed"
        | "password_changed_by_admin"
        | "password_reset"
        | "user_removed"
        | "device_removed"
        | "network_device_removed"
        | "mfa_totp_disabled"
        | "mfa_email_disabled"
        | "mfa_security_key_removed" => SiemSeverity::High,
        "settings_updated"
        | "settings_updated_partial"
        | "enterprise_settings_updated"
        | "api_token_added"
        | "api_token_removed"
        | "api_token_renamed"
        | "authentication_key_added"
        | "authentication_key_removed"
        | "authentication_key_renamed"
        | "password_changed"
        | "mfa_totp_enabled"
        | "mfa_email_enabled"
        | "mfa_security_key_added"
        | "group_added"
        | "group_modified"
        | "group_removed"
        | "group_member_added"
        | "group_member_removed"
        | "group_members_modified"
        | "groups_bulk_assigned"
        | "user_groups_modified"
        | "activity_log_stream_created"
        | "activity_log_stream_modified"
        | "activity_log_stream_removed"
        | "web_hook_added"
        | "web_hook_modified"
        | "web_hook_removed"
        | "web_hook_state_changed"
        | "open_id_app_added"
        | "open_id_app_removed"
        | "open_id_app_modified"
        | "open_id_app_state_changed"
        | "open_id_provider_removed"
        | "open_id_provider_modified"
        | "client_configuration_token_added"
        | "vpn_location_added"
        | "vpn_location_removed"
        | "vpn_location_modified"
        | "user_snat_binding_added"
        | "user_snat_binding_modified"
        | "user_snat_binding_removed"
        | "gateway_modified"
        | "gateway_disconnected"
        | "proxy_modified"
        | "proxy_disconnected"
        | "device_posture_created"
        | "device_posture_updated"
        | "device_posture_deleted"
        | "device_posture_duplicated"
        | "device_posture_locations_assigned"
        | "location_postures_assigned" => SiemSeverity::Medium,
        _ => SiemSeverity::Low,
    };

    let mut detections = Vec::new();

    if matches!(
        event,
        "user_login_failed" | "user_mfa_login_failed" | "vpn_client_mfa_failed"
    ) {
        detections.push(SiemDetectionRuleId::AuthenticationFailures);
    }

    if matches!(
        event,
        "recovery_code_used"
            | "mfa_disabled"
            | "user_mfa_disabled"
            | "mfa_totp_enabled"
            | "mfa_totp_disabled"
            | "mfa_email_enabled"
            | "mfa_email_disabled"
            | "mfa_security_key_added"
            | "mfa_security_key_removed"
            | "password_changed"
            | "password_changed_by_admin"
            | "password_reset"
            | "api_token_added"
            | "api_token_removed"
            | "api_token_renamed"
            | "authentication_key_added"
            | "authentication_key_removed"
            | "authentication_key_renamed"
    ) {
        detections.push(SiemDetectionRuleId::CredentialSecurityChanges);
    }

    if event == "device_posture_check_failed" {
        detections.push(SiemDetectionRuleId::PostureFailures);
    }

    if matches!(
        event,
        "gateway_deleted"
            | "gateway_modified"
            | "proxy_deleted"
            | "proxy_modified"
            | "gateway_disconnected"
            | "proxy_disconnected"
            | "settings_updated"
            | "settings_updated_partial"
            | "enterprise_settings_updated"
            | "group_added"
            | "group_modified"
            | "group_removed"
            | "group_member_added"
            | "group_member_removed"
            | "group_members_modified"
            | "groups_bulk_assigned"
            | "user_groups_modified"
            | "activity_log_stream_created"
            | "activity_log_stream_modified"
            | "activity_log_stream_removed"
            | "web_hook_added"
            | "web_hook_modified"
            | "web_hook_removed"
            | "web_hook_state_changed"
            | "open_id_app_added"
            | "open_id_app_removed"
            | "open_id_app_modified"
            | "open_id_app_state_changed"
            | "open_id_provider_removed"
            | "open_id_provider_modified"
            | "client_configuration_token_added"
            | "vpn_location_added"
            | "vpn_location_removed"
            | "vpn_location_modified"
            | "user_snat_binding_added"
            | "user_snat_binding_modified"
            | "user_snat_binding_removed"
            | "device_posture_created"
            | "device_posture_updated"
            | "device_posture_deleted"
            | "device_posture_duplicated"
            | "device_posture_locations_assigned"
            | "location_postures_assigned"
    ) {
        detections.push(SiemDetectionRuleId::InfrastructureChanges);
    }

    (severity, detections)
}

/// List activity log events
///
/// Supports filtering by time range, module, event type and username, plus a free-text search
/// over event descriptions. Each event also includes Core-derived SIEM severity and detection
/// metadata. These fields are additive and do not change Activity Log filtering or authorization.
#[utoipa::path(
    get,
    path = "/api/v1/activity_log",
    tag = "activity log",
    params(
        ("page" = Option<u32>, Query, description = "Page number. Defaults to 1."),
        ("per_page" = Option<u32>, Query, description = "Number of items per page, from 1 to 100. Defaults to 50."),
        ("from" = Option<String>, Query, description = "Start of the reported period as an RFC 3339 timestamp."),
        ("until" = Option<String>, Query, description = "End of the reported period as an RFC 3339 timestamp."),
        ("username" = Option<String>, Query, description = "Filter by username. Admins only."),
        ("event" = Option<String>, Query, description = "Filter by event type."),
        ("module" = Option<String>, Query, description = "Filter by module."),
        ("search" = Option<String>, Query, description = "Free-text search across username, location, module, event type, device, and description."),
        ("sort_by" = Option<String>, Query, description = "Sort key: `timestamp`, `username`, `location`, `ip`, `event`, `module`, or `device`. Defaults to `timestamp`."),
        ("sort_order" = Option<String>, Query, description = "Sort direction: `asc` or `desc`. Defaults to `desc`."),
    ),
    responses(
        (status = 200, description = "Paginated list of activity log events.", body = PaginatedApiResponse<ApiActivityLogEvent>),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 500, description = "Unable to list activity log events.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = []),
        ("api_token" = [])
    )
)]
pub async fn get_activity_log_events(
    session_info: SessionInfo,
    State(appstate): State<AppState>,
    pagination: Query<PaginationParams>,
    filters: Query<FilterParams>,
    sorting: Query<SortParams>,
) -> PaginatedApiResult<ApiActivityLogEvent> {
    let pagination = pagination.0;
    debug!("Fetching activity log with filters {filters:?} and pagination {pagination}");

    let visible_username = if session_info.is_admin {
        None
    } else {
        Some(session_info.user.username.clone())
    };

    let mut query_builder: QueryBuilder<Postgres> = QueryBuilder::new(
        "SELECT id, timestamp, user_id, username, location, ip, event, module, device, description \
        FROM activity_log_event WHERE 1=1 ",
    );

    if let Some(username) = &visible_username {
        query_builder
            .push(" AND username = ")
            .push_bind(username)
            .push(" ");
    }

    apply_filters(&mut query_builder, &filters);
    apply_sorting(&mut query_builder, &sorting);

    query_builder
        .push(" LIMIT ")
        .push_bind(i64::from(pagination.per_page()));
    query_builder
        .push(" OFFSET ")
        .push_bind(i64::from(pagination.offset()));

    let mut events = query_builder
        .build_query_as::<ApiActivityLogEvent>()
        .fetch_all(&appstate.pool)
        .await?;
    for event in &mut events {
        event.apply_siem_classification();
    }

    let mut count_query_builder: QueryBuilder<Postgres> =
        QueryBuilder::new("SELECT COUNT(*) FROM activity_log_event WHERE 1=1 ");
    if let Some(username) = &visible_username {
        count_query_builder
            .push(" AND username = ")
            .push_bind(username)
            .push(" ");
    }
    apply_filters(&mut count_query_builder, &filters);
    let total_items: i64 = count_query_builder
        .build_query_scalar()
        .fetch_one(&appstate.pool)
        .await?;

    Ok(PaginatedApiResponse::new(
        events,
        pagination,
        total_items as u32,
    ))
}

fn apply_filters(query_builder: &mut QueryBuilder<Postgres>, filters: &FilterParams) {
    debug!("Applying query filters: {filters:?}");

    if let Some(from) = filters.from {
        query_builder
            .push(" AND timestamp >= ")
            .push_bind(from.naive_utc());
    }
    if let Some(until) = filters.until {
        query_builder
            .push(" AND timestamp <= ")
            .push_bind(until.naive_utc());
    }

    if !filters.username.is_empty() {
        query_builder
            .push(" AND username = ANY(")
            .push_bind(filters.username.clone())
            .push(") ");
    }

    if !filters.location.is_empty() {
        query_builder
            .push(" AND location = ANY(")
            .push_bind(filters.location.clone())
            .push(") ");
    }

    if !filters.event.is_empty() {
        query_builder
            .push(" AND event = ANY(")
            .push_bind(filters.event.clone())
            .push(") ");
    }

    if !filters.module.is_empty() {
        query_builder
            .push(" AND module = ANY(")
            .push_bind(filters.module.clone())
            .push(") ");
    }

    if let Some(search_term) = &filters.search {
        query_builder
            .push(" AND CONCAT(username, ' ', location, ' ', module, ' ', event, ' ', device, ' ', description, ' ') ILIKE ")
            .push_bind(format!("%{search_term}%"))
            .push(" ");
    }
}

fn apply_sorting(query_builder: &mut QueryBuilder<Postgres>, sorting: &SortParams) {
    debug!("Applying query sorting: {sorting:?}");

    query_builder
        .push(" ORDER BY ")
        .push(sorting.sort_by.to_string())
        .push(" ")
        .push(sorting.sort_order.to_string())
        .push(", id ")
        .push(sorting.sort_order.to_string());
}

#[cfg(test)]
mod tests {
    use super::{SiemDetectionRuleId, SiemSeverity, classify_siem_event};

    #[test]
    fn classifies_critical_credential_event() {
        let (severity, detections) = classify_siem_event("mfa_disabled");

        assert_eq!(severity, SiemSeverity::Critical);
        assert_eq!(
            detections,
            vec![SiemDetectionRuleId::CredentialSecurityChanges]
        );
    }

    #[test]
    fn classifies_high_authentication_failure() {
        let (severity, detections) = classify_siem_event("user_login_failed");

        assert_eq!(severity, SiemSeverity::High);
        assert_eq!(detections, vec![SiemDetectionRuleId::AuthenticationFailures]);
    }

    #[test]
    fn classifies_posture_failure() {
        let (severity, detections) = classify_siem_event("device_posture_check_failed");

        assert_eq!(severity, SiemSeverity::High);
        assert_eq!(detections, vec![SiemDetectionRuleId::PostureFailures]);
    }

    #[test]
    fn classifies_medium_infrastructure_event() {
        let (severity, detections) = classify_siem_event("settings_updated");

        assert_eq!(severity, SiemSeverity::Medium);
        assert_eq!(detections, vec![SiemDetectionRuleId::InfrastructureChanges]);
    }

    #[test]
    fn classifies_mfa_method_removal_as_high_credential_change() {
        let (severity, detections) = classify_siem_event("mfa_security_key_removed");

        assert_eq!(severity, SiemSeverity::High);
        assert_eq!(
            detections,
            vec![SiemDetectionRuleId::CredentialSecurityChanges]
        );
    }

    #[test]
    fn classifies_logging_change_as_medium_infrastructure_change() {
        let (severity, detections) = classify_siem_event("activity_log_stream_removed");

        assert_eq!(severity, SiemSeverity::Medium);
        assert_eq!(detections, vec![SiemDetectionRuleId::InfrastructureChanges]);
    }

    #[test]
    fn keeps_unmapped_event_low_without_detection() {
        let (severity, detections) = classify_siem_event("user_login");

        assert_eq!(severity, SiemSeverity::Low);
        assert!(detections.is_empty());
    }
}
