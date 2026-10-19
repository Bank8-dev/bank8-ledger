// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Schedule tags + account schedule tags.
//! Tags are activation groups: a schedule attached to a tag runs only when
//! the tag is ACTIVE. Per-account tag overrides
//! (`account_schedule_tags`) take precedence over the schedule-level
//! association (design §5.1/§5.4).

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{emit_event, err_db, set_tenant_context, AppState};

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct ScheduleTagResponse {
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateScheduleTagRequest {
    pub name: String,
    #[serde(default = "default_tag_status")]
    pub status: String,
}
fn default_tag_status() -> String {
    "active".into()
}

/// `POST /v1/schedule-tags` - create a schedule tag (activation group).
#[utoipa::path(
    post,
    path = "/v1/schedule-tags",
    request_body = CreateScheduleTagRequest,
    responses(
        (status = 200, description = "Tag created", body = ScheduleTagResponse),
        (status = 409, description = "Tag name exists"),
        (status = 403, description = "Missing bank8:ledger:schedules:write scope"),
    ),
    security(("bank8:ledger:schedules:write" = [])),
    tag = "ledger",
)]
pub async fn create_schedule_tag(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateScheduleTagRequest>,
) -> Result<Json<ScheduleTagResponse>, (StatusCode, String)> {
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
        r#"INSERT INTO schedule_tags (env_id, name, status) VALUES ($1, $2, $3)
           RETURNING id, name, status, created_at"#,
    )
    .bind(a.env_id())
    .bind(&req.name)
    .bind(&req.status)
    .fetch_one(&mut *conn)
    .await;
    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            return Err((StatusCode::CONFLICT, "schedule tag already exists".into()));
        }
        Err(e) => return Err(err_db(e)),
    };
    let tag_id: Uuid = row.get("id");
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:scheduletag:created",
        serde_json::json!({ "tag_id": tag_id, "name": req.name }),
    )
    .await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(ScheduleTagResponse {
        id: tag_id,
        name: row.get("name"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }))
}

/// `GET /v1/schedule-tags` - list schedule tags.
#[utoipa::path(
    get,
    path = "/v1/schedule-tags",
    responses(
        (status = 200, description = "Schedule tags", body = [ScheduleTagResponse]),
        (status = 403, description = "Missing bank8:ledger:schedules:read scope"),
    ),
    security(("bank8:ledger:schedules:read" = [])),
    tag = "ledger",
)]
pub async fn list_schedule_tags(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ScheduleTagResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, name, status, created_at FROM schedule_tags WHERE env_id = $1 ORDER BY name"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| ScheduleTagResponse {
                id: r.get("id"),
                name: r.get("name"),
                status: r.get("status"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssociateScheduleTagRequest {
    pub schedule_id: Uuid,
}

/// `POST /v1/schedule-tags/{id}/assocs` - attach a tag to a schedule
/// (tag status ACTIVE/INACTIVE controls the schedule).
#[utoipa::path(
    post,
    path = "/v1/schedule-tags/{id}/assocs",
    request_body = AssociateScheduleTagRequest,
    responses(
        (status = 200, description = "Associated"),
        (status = 403, description = "Missing bank8:ledger:schedules:write scope"),
    ),
    security(("bank8:ledger:schedules:write" = [])),
    tag = "ledger",
)]
pub async fn associate_schedule_tag(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tag_id): Path<Uuid>,
    Json(req): Json<AssociateScheduleTagRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    sqlx::query(
        r#"INSERT INTO schedule_tag_assocs (env_id, tag_id, schedule_id) VALUES ($1, $2, $3)
           ON CONFLICT (tag_id, schedule_id) DO NOTHING"#,
    )
    .bind(a.env_id())
    .bind(tag_id)
    .bind(req.schedule_id)
    .execute(&mut *conn)
    .await
    .map_err(err_db)?;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(
        serde_json::json!({ "tag_id": tag_id, "schedule_id": req.schedule_id }),
    ))
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct AccountScheduleTagResponse {
    pub id: Uuid,
    pub account_id: Uuid,
    pub tag_id: Uuid,
    pub status: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertAccountScheduleTagRequest {
    pub tag_id: Uuid,
    #[serde(default = "default_tag_status")]
    pub status: String,
}

/// `POST /v1/account-schedule-tags` - create/override an account schedule tag.
#[utoipa::path(
    post,
    path = "/v1/accounts/{id}/schedule-tags",
    request_body = UpsertAccountScheduleTagRequest,
    params(("account_id" = Uuid, Path, description = "Account id (path variant: /v1/accounts/{id}/schedule-tags)")),
    responses(
        (status = 200, description = "Account schedule tag upserted", body = AccountScheduleTagResponse),
        (status = 403, description = "Missing bank8:ledger:schedules:write scope"),
    ),
    security(("bank8:ledger:schedules:write" = [])),
    tag = "ledger",
)]
pub async fn upsert_account_schedule_tag(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_id): Path<Uuid>,
    Json(req): Json<UpsertAccountScheduleTagRequest>,
) -> Result<Json<AccountScheduleTagResponse>, (StatusCode, String)> {
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
        r#"INSERT INTO account_schedule_tags (env_id, account_id, tag_id, status)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (account_id, tag_id) DO UPDATE SET status = EXCLUDED.status
           RETURNING id, account_id, tag_id, status"#,
    )
    .bind(a.env_id())
    .bind(account_id)
    .bind(req.tag_id)
    .bind(&req.status)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(AccountScheduleTagResponse {
        id: row.get("id"),
        account_id: row.get("account_id"),
        tag_id: row.get("tag_id"),
        status: row.get("status"),
    }))
}

/// `GET /v1/account-schedule-tags?account_id=` - list account schedule tags.
#[utoipa::path(
    get,
    path = "/v1/account-schedule-tags",
    responses(
        (status = 200, description = "Account schedule tags", body = [AccountScheduleTagResponse]),
        (status = 403, description = "Missing bank8:ledger:schedules:read scope"),
    ),
    security(("bank8:ledger:schedules:read" = [])),
    tag = "ledger",
)]
pub async fn list_account_schedule_tags(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AccountScheduleTagListQuery>,
) -> Result<Json<Vec<AccountScheduleTagResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, account_id, tag_id, status FROM account_schedule_tags
            WHERE env_id = $1 AND ($2::uuid IS NULL OR account_id = $2) ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id()).bind(q.account_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| AccountScheduleTagResponse {
                id: r.get("id"),
                account_id: r.get("account_id"),
                tag_id: r.get("tag_id"),
                status: r.get("status"),
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AccountScheduleTagListQuery {
    #[serde(default)]
    pub account_id: Option<Uuid>,
}
