// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Processing groups — EOD batching configuration.
//! Each group carries a `utc_offset`, `eod_cut_off`, `grace_period_minutes`
//! and a `paused` flag. Sentin8:Cron is UTC-only — timezone offsets are
//! applied ledger-side when slicing the schedule run by group (design §5.3b).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{emit_event, err_db, set_tenant_context, AppState};

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct ProcessingGroupResponse {
    pub id: Uuid,
    pub name: String,
    pub utc_offset: String,
    pub eod_cut_off: String,
    pub grace_period_minutes: i32,
    pub paused: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertProcessingGroupRequest {
    pub name: String,
    #[serde(default = "default_utc_offset")]
    pub utc_offset: String,
    #[serde(default = "default_eod_cut_off")]
    pub eod_cut_off: String,
    #[serde(default)]
    pub grace_period_minutes: i32,
    #[serde(default)]
    pub paused: bool,
}
fn default_utc_offset() -> String {
    "UTC".into()
}
fn default_eod_cut_off() -> String {
    "18:00".into()
}

/// `GET /v1/processing-groups` — list processing groups.
#[utoipa::path(
    get,
    path = "/v1/processing-groups",
    responses(
        (status = 200, description = "Processing groups", body = [ProcessingGroupResponse]),
        (status = 403, description = "Missing bank8:ledger:schedules:read scope"),
    ),
    security(("bank8:ledger:schedules:read" = [])),
    tag = "ledger",
)]
pub async fn list_processing_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProcessingGroupResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:schedules:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT id, name, utc_offset, eod_cut_off, grace_period_minutes, paused, updated_at
             FROM processing_groups WHERE env_id = $1 ORDER BY name"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| ProcessingGroupResponse {
                id: r.get("id"),
                name: r.get("name"),
                utc_offset: r.get("utc_offset"),
                eod_cut_off: r.get("eod_cut_off"),
                grace_period_minutes: r.get("grace_period_minutes"),
                paused: r.get("paused"),
                updated_at: r.get("updated_at"),
            })
            .collect(),
    ))
}

/// `POST /v1/processing-groups` — create/update a processing group.
#[utoipa::path(
    post,
    path = "/v1/processing-groups",
    request_body = UpsertProcessingGroupRequest,
    responses(
        (status = 200, description = "Processing group upserted", body = ProcessingGroupResponse),
        (status = 403, description = "Missing bank8:ledger:schedules:write scope"),
    ),
    security(("bank8:ledger:schedules:write" = [])),
    tag = "ledger",
)]
pub async fn upsert_processing_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpsertProcessingGroupRequest>,
) -> Result<Json<ProcessingGroupResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:schedules:write"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"INSERT INTO processing_groups (env_id, name, utc_offset, eod_cut_off, grace_period_minutes, paused)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (env_id, name) DO UPDATE
             SET utc_offset = EXCLUDED.utc_offset,
                 eod_cut_off = EXCLUDED.eod_cut_off,
                 grace_period_minutes = EXCLUDED.grace_period_minutes,
                 paused = EXCLUDED.paused,
                 updated_at = now()
           RETURNING id, name, utc_offset, eod_cut_off, grace_period_minutes, paused, updated_at"#,
    )
    .bind(a.env_id()).bind(&req.name).bind(&req.utc_offset).bind(&req.eod_cut_off)
    .bind(req.grace_period_minutes).bind(req.paused)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let group_id: Uuid = row.get("id");
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:processinggroup:updated",
        serde_json::json!({ "group_id": group_id, "name": req.name, "paused": req.paused }),
    )
    .await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(ProcessingGroupResponse {
        id: group_id,
        name: row.get("name"),
        utc_offset: row.get("utc_offset"),
        eod_cut_off: row.get("eod_cut_off"),
        grace_period_minutes: row.get("grace_period_minutes"),
        paused: row.get("paused"),
        updated_at: row.get("updated_at"),
    }))
}

async fn set_group_paused(
    state: &AppState,
    auth: &auth::AuthContext,
    id: Uuid,
    paused: bool,
) -> Result<Json<ProcessingGroupResponse>, (StatusCode, String)> {
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, auth.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"UPDATE processing_groups SET paused = $2, updated_at = now() WHERE id = $1 RETURNING id, name, utc_offset, eod_cut_off, grace_period_minutes, paused, updated_at"#,
    )
    .bind(id).bind(paused)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, format!("processing group {id} not found")))?;
    emit_event(
        &state.pool,
        auth.env_id(),
        "bank8:ledger:processinggroup:updated",
        serde_json::json!({ "group_id": id, "paused": paused }),
    )
    .await;
    Ok(Json(ProcessingGroupResponse {
        id: row.get("id"),
        name: row.get("name"),
        utc_offset: row.get("utc_offset"),
        eod_cut_off: row.get("eod_cut_off"),
        grace_period_minutes: row.get("grace_period_minutes"),
        paused: row.get("paused"),
        updated_at: row.get("updated_at"),
    }))
}

/// `POST /v1/processing-groups/{id}/pause` — pause EOD processing.
#[utoipa::path(
    post,
    path = "/v1/processing-groups/{id}/pause",
    responses((status = 200, description = "Paused", body = ProcessingGroupResponse)),
    security(("bank8:ledger:schedules:write" = [])),
    tag = "ledger",
)]
pub async fn pause_processing_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ProcessingGroupResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:schedules:write"),
    )
    .await?;
    set_group_paused(&state, &a, id, true).await
}

/// `POST /v1/processing-groups/{id}/resume` — resume EOD processing.
#[utoipa::path(
    post,
    path = "/v1/processing-groups/{id}/resume",
    responses((status = 200, description = "Resumed", body = ProcessingGroupResponse)),
    security(("bank8:ledger:schedules:write" = [])),
    tag = "ledger",
)]
pub async fn resume_processing_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ProcessingGroupResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:schedules:write"),
    )
    .await?;
    set_group_paused(&state, &a, id, false).await
}

// ── Unit tests (§8.6 conventions — pure logic, no DB) ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Processing-group defaults match the design (§5.3b): UTC offset, 18:00
    /// cut-off, zero grace, not paused.
    #[test]
    fn processing_group_defaults() {
        assert_eq!(default_utc_offset(), "UTC");
        assert_eq!(default_eod_cut_off(), "18:00");
        let req = UpsertProcessingGroupRequest {
            name: "g".into(),
            utc_offset: default_utc_offset(),
            eod_cut_off: default_eod_cut_off(),
            grace_period_minutes: 0,
            paused: false,
        };
        assert!(!req.paused);
        assert_eq!(req.grace_period_minutes, 0);
    }
}
