// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Adjustments and post-posting failure republish.
//! - Adjustments recompute an account state for backdated postings /
//! parameter changes by re-running the on-schedule modules from the
//! effective date and submitting a correction batch through the normal
//! posting path (`schedules::run_correction_for_account`).
//! - Post-posting hook failures are DLQ rows tagged
//! `failure_type='post_posting'` (written by the posting path); the
//! republish endpoint re-invokes the Sentin8:Func hook.

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
use crate::handlers::journal::append_journal_event;
use crate::handlers::{emit_event, err_db, set_tenant_context, AppState};

// ── Adjustments  ───────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct AdjustmentResponse {
    pub id: Uuid,
    pub account_id: Uuid,
    pub reason: String,
    pub effective_date: chrono::DateTime<chrono::Utc>,
    pub status: String,
    pub correction_batch_id: Option<Uuid>,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAdjustmentRequest {
    pub account_id: Uuid,
    pub reason: String,
    pub effective_date: chrono::DateTime<chrono::Utc>,
}

/// `POST /v1/adjustments` - create an adjustment: recompute the account state
/// for backdated postings/parameter changes by re-running the on-schedule
/// modules from the effective date and submitting a correction batch.
#[utoipa::path(
    post,
    path = "/v1/adjustments",
    request_body = CreateAdjustmentRequest,
    responses(
        (status = 200, description = "Adjustment created and applied (correction batch submitted)", body = AdjustmentResponse),
        (status = 400, description = "Invalid request"),
        (status = 403, description = "Missing bank8:ledger:postings:write scope"),
    ),
    security(("bank8:ledger:postings:write" = [])),
    tag = "ledger",
)]
pub async fn create_adjustment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAdjustmentRequest>,
) -> Result<Json<AdjustmentResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:write"),
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"INSERT INTO adjustments (env_id, account_id, reason, effective_date)
           VALUES ($1, $2, $3, $4)
           RETURNING id, account_id, reason, effective_date, status, correction_batch_id, error_message, created_at"#,
    )
    .bind(a.env_id()).bind(req.account_id).bind(&req.reason).bind(req.effective_date)
    .fetch_one(&mut *tx)
    .await
    .map_err(err_db)?;
    let adjustment_id: Uuid = row.get("id");

    // Correction computation: re-run the account's on-schedule
    // modules from the effective date to today, submitting the generated
    // posting instructions as one atomic correction batch. The schedule
    // engine (`run_scheduled_work`) already implements the
    // "generate postings from on-schedule modules" logic - the adjustment
    // drives it for this account and records the resulting batch id.
    let correction =
        crate::handlers::schedules::run_correction_for_account(&state, a.env_id(), req.account_id)
            .await;
    let (status, correction_batch_id, error_message) = match correction {
        Ok(batch_id) => ("applied", Some(batch_id), None),
        Err(e) => ("failed", None, Some(e)),
    };
    sqlx::query(
        "UPDATE adjustments SET status = $2, correction_batch_id = $3, error_message = $4, updated_at = now() WHERE id = $1",
    )
    .bind(adjustment_id).bind(status).bind(correction_batch_id).bind(error_message.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;

    append_journal_event(&mut tx, a.env_id(), "adjustment", adjustment_id, "create",
        &serde_json::json!({ "account_id": req.account_id, "reason": req.reason, "status": status }))
        .await?;
    tx.commit().await.map_err(err_db)?;

    emit_event(&state.pool, a.env_id(), "bank8:ledger:adjustment:created",
        serde_json::json!({ "adjustment_id": adjustment_id, "account_id": req.account_id, "reason": req.reason }))
        .await;

    /* removed misplaced commit */
    Ok(Json(AdjustmentResponse {
        id: adjustment_id,
        account_id: req.account_id,
        reason: req.reason,
        effective_date: req.effective_date,
        status: status.into(),
        correction_batch_id,
        error_message,
        created_at: row.get("created_at"),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListAdjustmentsQuery {
    #[serde(default)]
    pub account_id: Option<Uuid>,
}

/// `GET /v1/adjustments` - list adjustments (with `:batchGet` variant).
#[utoipa::path(
    get,
    path = "/v1/adjustments",
    responses(
        (status = 200, description = "Adjustments (newest first)", body = [AdjustmentResponse]),
        (status = 403, description = "Missing bank8:ledger:postings:read scope"),
    ),
    security(("bank8:ledger:postings:read" = [])),
    tag = "ledger",
)]
pub async fn list_adjustments(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListAdjustmentsQuery>,
) -> Result<Json<Vec<AdjustmentResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT id, account_id, reason, effective_date, status, correction_batch_id, error_message, created_at
             FROM adjustments
            WHERE ($1::uuid IS NULL OR account_id = $1)
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(q.account_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| AdjustmentResponse {
                id: r.get("id"),
                account_id: r.get("account_id"),
                reason: r.get("reason"),
                effective_date: r.get("effective_date"),
                status: r.get("status"),
                correction_batch_id: r.get("correction_batch_id"),
                error_message: r.get("error_message"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

/// `GET /v1/adjustments/{id}` - adjustment detail.
#[utoipa::path(
    get,
    path = "/v1/adjustments/{id}",
    responses(
        (status = 200, description = "Adjustment", body = AdjustmentResponse),
        (status = 404, description = "Not found"),
    ),
    security(("bank8:ledger:postings:read" = [])),
    tag = "ledger",
)]
pub async fn get_adjustment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<AdjustmentResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"SELECT id, account_id, reason, effective_date, status, correction_batch_id, error_message, created_at
             FROM adjustments WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, format!("adjustment {id} not found")))?;
    Ok(Json(AdjustmentResponse {
        id: row.get("id"),
        account_id: row.get("account_id"),
        reason: row.get("reason"),
        effective_date: row.get("effective_date"),
        status: row.get("status"),
        correction_batch_id: row.get("correction_batch_id"),
        error_message: row.get("error_message"),
        created_at: row.get("created_at"),
    }))
}

/// `POST /v1/adjustments:bulkRetry` - retry failed adjustments (Sentin8 Jobs
/// pattern).
#[utoipa::path(
    post,
    path = "/v1/adjustments/bulk-retry",
    responses(
        (status = 200, description = "Retried count"),
        (status = 403, description = "Missing bank8:ledger:postings:write scope"),
    ),
    security(("bank8:ledger:postings:write" = [])),
    tag = "ledger",
)]
pub async fn bulk_retry_adjustments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:write"),
    )
    .await?;
    let failed = sqlx::query(
        r#"SELECT id, account_id FROM adjustments WHERE env_id = $1 AND status = 'failed'"#,
    )
    .bind(a.env_id())
    .fetch_all(&state.pool)
    .await
    .map_err(err_db)?;
    let mut retried = 0i64;
    for row in &failed {
        let adj_id: Uuid = row.get("id");
        let account_id: Uuid = row.get("account_id");
        let correction =
            crate::handlers::schedules::run_correction_for_account(&state, a.env_id(), account_id)
                .await;
        let (status, batch_id, error_message) = match correction {
            Ok(b) => {
                retried += 1;
                ("applied", Some(b), None)
            }
            Err(e) => ("failed", None, Some(e)),
        };
        sqlx::query(
            "UPDATE adjustments SET status = $2, correction_batch_id = $3, error_message = $4, updated_at = now() WHERE id = $1",
        )
        .bind(adj_id).bind(status).bind(batch_id).bind(error_message)
        .execute(&state.pool)
        .await
        .map_err(err_db)?;
    }
    Ok(Json(
        serde_json::json!({ "retried": retried, "failed_total": failed.len() }),
    ))
}

// ── Post-posting failures - DLQ view with failure_type=post_posting ──

/// `GET /v1/post-posting-failures` - list post-posting hook failures.
#[utoipa::path(
    get,
    path = "/v1/post-posting-failures",
    responses(
        (status = 200, description = "Post-posting hook failures (DLQ subset)", body = [JsonValue]),
        (status = 403, description = "Missing bank8:ledger:postings:read scope"),
    ),
    security(("bank8:ledger:postings:read" = [])),
    tag = "ledger",
)]
pub async fn list_post_posting_failures(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<JsonValue>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    // Post-posting hook failures are DLQ rows tagged with
    // failure_type='post_posting' (written by the posting path when the
    // post-commit hook call fails with DLQ semantics).
    let rows = sqlx::query(
        r#"SELECT id, payload, error_message, created_at
             FROM dlq WHERE env_id = $1 AND COALESCE(payload->>'failure_type', '') = 'post_posting'
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let failures: Vec<JsonValue> = rows
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            let payload: JsonValue = r.get("payload");
            let error_message: Option<String> = r.get("error_message");
            let created_at: chrono::DateTime<chrono::Utc> = r.get("created_at");
            serde_json::json!({
                "id": id,
                "payload": payload,
                "error_message": error_message,
                "created_at": created_at,
            })
        })
        .collect();
    Ok(Json(failures))
}

/// `POST /v1/post-posting-failures/{id}/republish` - re-run the post-posting
/// hook for a committed batch (delegates to Sentin8:Func).
#[utoipa::path(
    post,
    path = "/v1/post-posting-failures/{id}/republish",
    responses(
        (status = 200, description = "Hook re-invoked"),
        (status = 404, description = "Failure not found"),
    ),
    security(("bank8:ledger:postings:write" = [])),
    tag = "ledger",
)]
pub async fn republish_post_posting_failure(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:write"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"SELECT payload FROM dlq WHERE id = $1 AND env_id = $2
             AND COALESCE(payload->>'failure_type', '') = 'post_posting'"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((
        StatusCode::NOT_FOUND,
        format!("post-posting failure {id} not found"),
    ))?;
    let payload: JsonValue = row.get("payload");
    let posting_id = payload
        .get("posting_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let module_id = payload
        .get("module_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let reinvoked = crate::func_hooks::republish_post_posting(
        &state.config,
        a.env_id(),
        &posting_id,
        &module_id,
    )
    .await;
    sqlx::query("DELETE FROM dlq WHERE id = $1 AND env_id = $2")
        .bind(id)
        .bind(a.env_id())
        .execute(&mut *conn)
        .await
        .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(
        serde_json::json!({ "id": id, "posting_id": posting_id, "reinvoked": reinvoked }),
    ))
}
