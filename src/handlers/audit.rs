// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Audit handlers — audit events and action logs.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use sqlx::Row;
use utoipa::ToSchema;

use crate::auth;
use crate::handlers::{err_db, set_tenant_context, AppState};

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct AuditEventResponse {
    pub id: uuid::Uuid,
    pub actor_user_id: Option<String>,
    pub action: String,
    pub target_resource_type: Option<String>,
    pub target_resource_id: Option<String>,
    pub correlation_id: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListAuditQuery {
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub target_resource_type: Option<String>,
}

/// `GET /v1/audit` — query audit events.
#[utoipa::path(
    get,
    path = "/v1/audit",
    params(
        ("action" = Option<String>, Query, description = "Filter by action"),
        ("target_resource_type" = Option<String>, Query, description = "Filter by target resource type"),
    ),
    responses(
        (status = 200, description = "Audit events", body = [AuditEventResponse]),
        (status = 403, description = "Missing bank8:ledger:audit:read scope"),
    ),
    security(("bank8:ledger:audit:read" = [])),
    tag = "ledger",
)]
pub async fn list_audit_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListAuditQuery>,
) -> Result<Json<Vec<AuditEventResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:audit:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT id, actor_user_id, action, target_resource_type, target_resource_id, correlation_id, timestamp
             FROM audit_events
            WHERE ($1::text IS NULL OR action = $1)
              AND ($2::text IS NULL OR target_resource_type = $2)
            ORDER BY timestamp DESC LIMIT 200"#,
    )
    .bind(q.action.as_deref()).bind(q.target_resource_type.as_deref())
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| AuditEventResponse {
                id: r.get("id"),
                actor_user_id: r.get("actor_user_id"),
                action: r.get("action"),
                target_resource_type: r.get("target_resource_type"),
                target_resource_id: r.get("target_resource_id"),
                correlation_id: r.get("correlation_id"),
                timestamp: r.get("timestamp"),
            })
            .collect(),
    ))
}

// ── Action logs  ──────────────────────────────────────────────────

/// `GET /v1/audit/action-logs` — action-filtered audit view (business Audit
/// API `action_logs`).
#[utoipa::path(
    get,
    path = "/v1/audit/action-logs",
    params(("action" = Option<String>, Query, description = "Filter by action")),
    responses(
        (status = 200, description = "Action logs", body = [AuditEventResponse]),
        (status = 403, description = "Missing bank8:ledger:audit:read scope"),
    ),
    security(("bank8:ledger:audit:read" = [])),
    tag = "ledger",
)]
pub async fn list_action_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ActionLogQuery>,
) -> Result<Json<Vec<AuditEventResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:audit:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT id, actor_user_id, action, target_resource_type, target_resource_id, correlation_id, timestamp
             FROM audit_events
            WHERE env_id = $1 AND ($2::text IS NULL OR action = $2)
            ORDER BY timestamp DESC LIMIT 200"#,
    )
    .bind(a.env_id()).bind(q.action.as_deref())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| AuditEventResponse {
                id: r.get("id"),
                actor_user_id: r.get("actor_user_id"),
                action: r.get("action"),
                target_resource_type: r.get("target_resource_type"),
                target_resource_id: r.get("target_resource_id"),
                correlation_id: r.get("correlation_id"),
                timestamp: r.get("timestamp"),
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ActionLogQuery {
    #[serde(default)]
    pub action: Option<String>,
}
