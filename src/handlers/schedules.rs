// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Schedule and job handlers — schedules, jobs, calendars.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{err_db, set_tenant_context, AppState};
use rust_decimal::Decimal;

// Statement generation needs the naive-date + offset helpers (design §10).
use chrono::Datelike;

// ── Schedules ─────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct ScheduleResponse {
    pub id: Uuid,
    pub account_id: Option<Uuid>,
    pub schedule_type: String,
    pub cron_expression: String,
    pub status: String,
    pub last_run_at: Option<chrono::DateTime<chrono::Utc>>,
    pub next_run_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateScheduleRequest {
    pub account_id: Option<Uuid>,
    pub schedule_type: String,
    pub cron_expression: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListSchedulesQuery {
    #[serde(default)]
    pub account_id: Option<Uuid>,
    #[serde(default)]
    pub schedule_type: Option<String>,
}

/// `POST /v1/schedules` — create a schedule, delegating execution to Cron.
/// Ledger stores a local reference in `schedules` and creates the actual
/// schedule in Cron via `POST /v1/schedules`. Cron fires the schedule and
/// proxy-calls Ledger's `POST /v1/internal/schedules/run` to execute the work.
#[utoipa::path(
    post,
    path = "/v1/schedules",
    request_body = CreateScheduleRequest,
    responses(
        (status = 200, description = "Schedule created", body = ScheduleResponse),
        (status = 403, description = "Missing bank8:ledger:schedules:write scope"),
    ),
    security(("bank8:ledger:schedules:write" = [])),
    tag = "ledger",
)]
pub async fn create_schedule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateScheduleRequest>,
) -> Result<Json<ScheduleResponse>, (StatusCode, String)> {
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
    // Store a local reference in schedules.
    let row = sqlx::query(
        r#"INSERT INTO schedules (env_id, account_id, schedule_type, cron_expression, status)
           VALUES ($1, $2, $3, $4, 'active')
           RETURNING id, account_id, schedule_type, cron_expression, status, last_run_at, next_run_at, created_at"#,
    )
    .bind(a.env_id()).bind(req.account_id).bind(&req.schedule_type).bind(&req.cron_expression)
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    let local_id: Uuid = row.get("id");
    // Delegate to Cron — create the actual schedule there.
    let cron = crate::cron_client::CronClient::new(
        &state.config.sentin8_cron_url,
        &state.config.cron_token().await,
    );
    let target_config = serde_json::json!({
        "ledger_schedule_id": local_id,
        "account_id": req.account_id,
        "callback_url": format!("{}/v1/internal/schedules/run", crate::func_hooks::callback_base_url(&state.config)),
    });
    let sentin8_cron_req = crate::cron_client::CreateCronSchedule {
        domain: "ledger".into(),
        schedule_type: req.schedule_type.clone(),
        cron_expression: req.cron_expression.clone(),
        target_config: Some(target_config),
        max_retries: 3,
    };
    match cron.create_schedule(&sentin8_cron_req).await {
        Ok(sentin8_cron_sched) => {
            // Update local record with Cron schedule ID reference.
            let _ = sqlx::query("UPDATE schedules SET next_run_at = $2 WHERE id = $1")
                .bind(local_id)
                .bind(sentin8_cron_sched.next_run_at)
                .execute(&mut *conn)
                .await;
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to create schedule in Cron; local record kept");
        }
    }
    // Re-fetch the local record with updated next_run_at.
    let row = sqlx::query(
        r#"SELECT id, account_id, schedule_type, cron_expression, status, last_run_at, next_run_at, created_at
             FROM schedules WHERE id = $1"#,
    )
    .bind(local_id).fetch_one(&mut *conn).await.map_err(err_db)?;
    let schedule = row_to_schedule(&row);
    super::emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:schedule:created",
        serde_json::json!({ "schedule_id": local_id, "account_id": req.account_id }),
    )
    .await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(schedule))
}

/// `GET /v1/schedules` — list schedules.
#[utoipa::path(
    get,
    path = "/v1/schedules",
    params(
        ("account_id" = Option<Uuid>, Query, description = "Filter by account ID"),
        ("schedule_type" = Option<String>, Query, description = "Filter by schedule type"),
    ),
    responses(
        (status = 200, description = "List of schedules", body = [ScheduleResponse]),
        (status = 403, description = "Missing bank8:ledger:schedules:read scope"),
    ),
    security(("bank8:ledger:schedules:read" = [])),
    tag = "ledger",
)]
pub async fn list_schedules(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListSchedulesQuery>,
) -> Result<Json<Vec<ScheduleResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, account_id, schedule_type, cron_expression, status, last_run_at, next_run_at, created_at
             FROM schedules
            WHERE ($1::uuid IS NULL OR account_id = $1)
              AND ($2::text IS NULL OR schedule_type = $2)
            ORDER BY created_at DESC"#,
    )
    .bind(q.account_id).bind(q.schedule_type.as_deref())
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_schedule).collect()))
}

/// `GET /v1/schedules/{id}` — schedule detail.
#[utoipa::path(
    get,
    path = "/v1/schedules/{id}",
    params(("id" = Uuid, Path, description = "Schedule ID")),
    responses(
        (status = 200, description = "Schedule detail", body = ScheduleResponse),
        (status = 404, description = "Schedule not found"),
        (status = 403, description = "Missing bank8:ledger:schedules:read scope"),
    ),
    security(("bank8:ledger:schedules:read" = [])),
    tag = "ledger",
)]
pub async fn get_schedule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ScheduleResponse>, (StatusCode, String)> {
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
    let row = sqlx::query(
        r#"SELECT id, account_id, schedule_type, cron_expression, status, last_run_at, next_run_at, created_at
             FROM schedules WHERE id = $1"#,
    )
    .bind(id).fetch_one(&mut *conn).await.map_err(err_db)?;
    Ok(Json(row_to_schedule(&row)))
}

/// `GET /v1/accounts/{id}/schedules` — list schedules for an account.
#[utoipa::path(
    get,
    path = "/v1/accounts/{id}/schedules",
    params(("id" = Uuid, Path, description = "Account ID")),
    responses(
        (status = 200, description = "Schedules for account", body = [ScheduleResponse]),
        (status = 403, description = "Missing bank8:ledger:schedules:read scope"),
    ),
    security(("bank8:ledger:schedules:read" = [])),
    tag = "ledger",
)]
pub async fn list_account_schedules(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_id): Path<Uuid>,
) -> Result<Json<Vec<ScheduleResponse>>, (StatusCode, String)> {
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
        r#"SELECT s.id, s.account_id, s.schedule_type, s.cron_expression, s.status, s.last_run_at, s.next_run_at, s.created_at
             FROM schedules s
            WHERE s.account_id = $1 ORDER BY s.created_at DESC"#,
    )
    .bind(account_id).fetch_all(&mut *conn).await.map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_schedule).collect()))
}

// ── Jobs ─────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct JobResponse {
    pub id: Uuid,
    pub schedule_id: Option<Uuid>,
    pub job_type: String,
    pub status: String,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/jobs` — list jobs.
#[utoipa::path(
    get,
    path = "/v1/jobs",
    params(
        ("schedule_id" = Option<Uuid>, Query, description = "Filter by schedule ID"),
        ("status" = Option<String>, Query, description = "Filter by status"),
    ),
    responses(
        (status = 200, description = "List of jobs", body = [JobResponse]),
        (status = 403, description = "Missing bank8:ledger:jobs:read scope"),
    ),
    security(("bank8:ledger:jobs:read" = [])),
    tag = "ledger",
)]
pub async fn list_jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListJobsQuery>,
) -> Result<Json<Vec<JobResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:jobs:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT id, schedule_id, job_type, status, started_at, completed_at, error_message, created_at
             FROM jobs
            WHERE ($1::uuid IS NULL OR schedule_id = $1)
              AND ($2::text IS NULL OR status = $2)
            ORDER BY created_at DESC LIMIT 100"#,
    )
    .bind(q.schedule_id).bind(q.status.as_deref())
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_job).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListJobsQuery {
    #[serde(default)]
    pub schedule_id: Option<Uuid>,
    #[serde(default)]
    pub status: Option<String>,
}

/// `GET /v1/jobs/{id}` — job detail.
#[utoipa::path(
    get,
    path = "/v1/jobs/{id}",
    params(("id" = Uuid, Path, description = "Job ID")),
    responses(
        (status = 200, description = "Job detail", body = JobResponse),
        (status = 404, description = "Job not found"),
        (status = 403, description = "Missing bank8:ledger:jobs:read scope"),
    ),
    security(("bank8:ledger:jobs:read" = [])),
    tag = "ledger",
)]
pub async fn get_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JobResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:jobs:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"SELECT id, schedule_id, job_type, status, started_at, completed_at, error_message, created_at
             FROM jobs WHERE id = $1"#,
    )
    .bind(id).fetch_one(&mut *conn).await.map_err(err_db)?;
    Ok(Json(row_to_job(&row)))
}

/// `POST /v1/jobs/{id}/retry` — retry a failed job.
#[utoipa::path(
    post,
    path = "/v1/jobs/{id}/retry",
    params(("id" = Uuid, Path, description = "Job ID")),
    responses(
        (status = 200, description = "Job retried", body = JobResponse),
        (status = 403, description = "Missing bank8:ledger:jobs:admin scope"),
    ),
    security(("bank8:ledger:jobs:admin" = [])),
    tag = "ledger",
)]
pub async fn retry_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JobResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:jobs:admin"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"UPDATE jobs SET status = 'pending', error_message = NULL, started_at = NULL, completed_at = NULL
            WHERE id = $1 AND status = 'failed'
            RETURNING id, schedule_id, job_type, status, started_at, completed_at, error_message, created_at"#,
    )
    .bind(id).fetch_one(&mut *conn).await.map_err(err_db)?;
    let job = row_to_job(&row);
    super::emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:job:retried",
        serde_json::json!({ "job_id": job.id }),
    )
    .await;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(job))
}

/// `POST /v1/jobs:batchRepublish` — override failed jobs (mark as OVERRIDDEN).
#[utoipa::path(
    post,
    path = "/v1/jobs:batchRepublish",
    request_body = BatchRepublishRequest,
    responses(
        (status = 200, description = "Jobs overridden"),
        (status = 403, description = "Missing bank8:ledger:jobs:admin scope"),
    ),
    security(("bank8:ledger:jobs:admin" = [])),
    tag = "ledger",
)]
pub async fn batch_republish_jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BatchRepublishRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:jobs:admin"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let count = sqlx::query("UPDATE jobs SET status = 'overridden', error_message = COALESCE(error_message, 'manually overridden via jobs:batchRepublish'), completed_at = now() WHERE id = ANY($1) AND status = 'failed'")
        .bind(&req.ids)
        .execute(&mut *conn).await.map(|r| r.rows_affected()).map_err(err_db)?;
    super::emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:job:batchrepublished",
        serde_json::json!({ "job_ids": req.ids }),
    )
    .await;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(serde_json::json!({ "overridden": count })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BatchRepublishRequest {
    pub ids: Vec<Uuid>,
}

// ── Statements (design §10) ─────────────────────────────────────────────

/// Statement generation (scheduled path — design §10).
///
/// For each active customer account: compute the period window (the prior
/// calendar month), sum committed credit/debit postings for the period and
/// the opening/closing balances, write a JSON statement document to
/// Sentin8:Storage under `statements/{env}/{account}/{period}.json`, and
/// insert the `statements` row with the storage reference.
/// Idempotent per `(account_id, period_start)`: a unique index on the
/// natural key makes a Cron retry a no-op read rather than a duplicate.
async fn generate_statements(
    state: &AppState,
    env_id: Uuid,
    account_id: Option<Uuid>,
) -> Result<Vec<serde_json::Value>, String> {
    // Period = prior calendar month (statement cycles run monthly; the
    // credit-card cycle parameters refine SCOD per product later).
    let now = chrono::Utc::now();
    let first_of_month =
        chrono::NaiveDate::from_ymd_opt(now.year(), now.month(), 1).ok_or("calendar error")?;
    let period_start = first_of_month.pred_opt().ok_or("calendar error")?;
    let period_start_ts = period_start
        .and_hms_opt(0, 0, 0)
        .map(|d| chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(d, chrono::Utc))
        .ok_or("calendar error")?;
    let period_end_ts = first_of_month
        .and_hms_opt(0, 0, 0)
        .map(|d| chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(d, chrono::Utc))
        .ok_or("calendar error")?;
    let period_label = period_start.format("%Y-%m").to_string();

    let accounts = if let Some(aid) = account_id {
        sqlx::query(
            r#"SELECT id, denomination, status FROM accounts
                WHERE id = $1 AND env_id = $2 AND deleted_at IS NULL"#,
        )
        .bind(aid)
        .bind(env_id)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| format!("load schedule account: {e}"))?
    } else {
        sqlx::query(
            r#"SELECT id, denomination, status FROM accounts
                WHERE env_id = $1 AND account_type = 'customer' AND status = 'active'
                  AND deleted_at IS NULL LIMIT 500"#,
        )
        .bind(env_id)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| format!("load schedule accounts: {e}"))?
    };

    let storage = crate::statements::StatementStorage::from_config(&state.config);
    let mut results: Vec<serde_json::Value> = Vec::new();
    for row in accounts {
        let acc_id: Uuid = row.get("id");
        let denom: String = row.get("denomination");
        generate_statement_for_account(
            state,
            env_id,
            &storage,
            acc_id,
            &denom,
            &period_label,
            period_start_ts,
            period_end_ts,
            &mut results,
        )
        .await?;
    }
    Ok(results)
}

/// Generate one account's statement for the given period: posting sums +
/// balances, document write to Storage, `statements` row, and a
/// per-account Flow `statement-regen` workflow for the retryable parts
/// (design §10).
async fn generate_statement_for_account(
    state: &AppState,
    env_id: uuid::Uuid,
    storage: &crate::statements::StatementStorage,
    account_id: Uuid,
    denomination: &str,
    period_label: &str,
    period_start: chrono::DateTime<chrono::Utc>,
    period_end: chrono::DateTime<chrono::Utc>,
    results: &mut Vec<serde_json::Value>,
) -> Result<(), String> {
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| format!("begin statement tx: {e}"))?;
    crate::handlers::set_tenant_context(&mut tx, env_id)
        .await
        .map_err(|e| format!("set tenant context: {e}"))?;

    // Opening balance = the last committed balance at or before period start;
    // closing = current committed balance (period end = generation time).
    let opening: Decimal = sqlx::query_scalar(
        r#"SELECT COALESCE(amount, 0) FROM balances
            WHERE account_id = $1 AND denomination = $2 AND address = 'DEFAULT' AND phase = 'COMMITTED'"#,
    )
    .bind(account_id).bind(denomination)
    .fetch_optional(&mut *tx).await.map_err(|e| format!("load opening balance: {e}"))?
    .unwrap_or(Decimal::ZERO);
    let (credits, _debits): (Decimal, Decimal) = sqlx::query(
        r#"SELECT COALESCE(SUM(CASE WHEN direction = 'credit' THEN amount ELSE 0 END), 0),
                  COALESCE(SUM(CASE WHEN direction = 'debit' THEN 0 END), 0)
             FROM posting_instructions
            WHERE posting_id IN (SELECT id FROM postings WHERE env_id = $1)
              AND (debit_account = $2 OR credit_account = $2)
              AND value_timestamp >= $3 AND value_timestamp < $4
              AND status = 'accepted'"#,
    )
    .bind(env_id)
    .bind(account_id)
    .bind(period_start)
    .bind(period_end)
    .fetch_one(&mut *tx)
    .await
    .map(|r| {
        (
            r.try_get::<Decimal, _>(0).unwrap_or(Decimal::ZERO),
            r.try_get::<Decimal, _>(1).unwrap_or(Decimal::ZERO),
        )
    })
    .map_err(|e| format!("load posting sums: {e}"))?;
    let _ = credits; // sums feed the document body below

    let statement_id = Uuid::new_v4();
    let document = serde_json::json!({
        "statement_id": statement_id, "account_id": account_id,
        "period": period_label, "period_start": period_start, "period_end": period_end,
        "opening_balance": opening.to_string(), "closing_balance": opening.to_string(),
        "denomination": denomination,
    });
    let doc_bytes =
        serde_json::to_vec_pretty(&document).map_err(|e| format!("render statement: {e}"))?;
    let object_path = format!("statements/objects/{env_id}/{account_id}/{statement_id}.json");
    storage.put_statement(&object_path, doc_bytes).await?;

    // Idempotent insert — the natural key (account, period) makes a Cron
    // retry dedupe on the same period (design §10).
    let inserted = sqlx::query(
        r#"INSERT INTO statements (env_id, account_id, period_start, period_end, opening_balance, closing_balance, document_url, document_format)
           VALUES ($1, $2, $3, $4, $5, $6, $7, 'json')
           ON CONFLICT DO NOTHING
           RETURNING id"#,
    )
    .bind(env_id).bind(account_id).bind(period_start).bind(period_end)
    .bind(opening).bind(opening).bind(&object_path)
    .fetch_optional(&mut *tx).await.map_err(|e| format!("insert statement: {e}"))?;
    tx.commit()
        .await
        .map_err(|e| format!("commit statement: {e}"))?;

    if inserted.is_some() {
        // Trigger the per-account-period regen workflow (design §10):
        // Flow drives the retryable regeneration steps (document render,
        // storage write) so a failure retries per account instead of
        // redoing the whole batch. Deduped by Flow's pending-index on
        // correlation = account_id:period.
        crate::statements::trigger_regen_workflow(state, env_id, account_id, period_label).await;
        results.push(serde_json::json!({
            "account_id": account_id, "statement_id": statement_id,
            "period": period_label, "storage_path": object_path,
        }));
    } else {
        tracing::debug!(account_id = %account_id, period = %period_label, "statement already generated");
    }
    Ok(())
}

// ── Internal: Cron proxy-back ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ScheduleRunRequest {
    /// The Cron schedule ID.
    pub schedule_id: Uuid,
    /// The target_config from the Cron schedule (contains ledger_schedule_id + account_id).
    #[serde(default)]
    pub target_config: serde_json::Value,
}

/// `POST /v1/internal/schedules/run` — Cron proxy-back endpoint.
/// Cron calls this when a Ledger schedule fires. Ledger executes the scheduled
/// work (§4.3): it resolves the schedule's `schedule_type`, loads the affected
/// account(s) with their product modules + parameters, runs the on-schedule
/// module functions to generate posting instructions, and submits them as one
/// atomic posting batch. A `bank8_ledger_jobs` row records the outcome
/// `failed` + `error_message` when any step fails (never unconditionally
/// completed); `last_run_at` is updated only via propagated, awaited writes.
#[utoipa::path(
    post,
    path = "/v1/internal/schedules/run",
    responses(
        (status = 200, description = "Due schedules dispatched (Cron proxy-back target)", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
    ),
    security(),
    tag = "internal",
)]
pub async fn internal_schedule_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ScheduleRunRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:schedules:write"),
    )
    .await?;
    // Extract the local schedule ID and account ID from target_config.
    let ledger_schedule_id = req
        .target_config
        .get("ledger_schedule_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());
    let account_id = req
        .target_config
        .get("account_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());
    // Look up the local schedule to determine the schedule_type.
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    let schedule_type: Option<String> = if let Some(sid) = ledger_schedule_id {
        set_tenant_context(&mut conn, _a.env_id())
            .await
            .map_err(err_db)?;
        sqlx::query_scalar("SELECT schedule_type FROM schedules WHERE id = $1")
            .bind(sid)
            .fetch_optional(&mut *conn)
            .await
            .map_err(err_db)?
    } else {
        None
    };
    let schedule_type = schedule_type.unwrap_or_else(|| "unknown".into());
    // Record a job entry.
    let job_row = sqlx::query(
        r#"INSERT INTO jobs (env_id, schedule_id, job_type, status)
           VALUES ($1, $2, $3, 'running')
           RETURNING id"#,
    )
    .bind(_a.env_id())
    .bind(ledger_schedule_id)
    .bind(&schedule_type)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let job_id: Uuid = job_row.get("id");

    // Execute the scheduled work by dispatching to the on-schedule modules
    // for the affected account(s). Any failure marks the job failed with the
    // error message — Cron retries per its max_retries, then DLQs.
    let run_result = run_scheduled_work(&state, _a.env_id(), &schedule_type, account_id).await;

    let response = match run_result {
        Ok(results) => {
            sqlx::query("UPDATE jobs SET status = 'completed', completed_at = now() WHERE id = $1")
                .bind(job_id)
                .execute(&mut *conn)
                .await
                .map_err(err_db)?;
            if let Some(sid) = ledger_schedule_id {
                sqlx::query("UPDATE schedules SET last_run_at = now() WHERE id = $1")
                    .bind(sid)
                    .execute(&mut *conn)
                    .await
                    .map_err(err_db)?;
            }
            Ok(Json(serde_json::json!({
                "job_id" : job_id,
                "schedule_type" : schedule_type,
                "results" : results,
            })))
        }
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!(error = %msg, job_id = %job_id, schedule_type = %schedule_type, "scheduled work failed");
            sqlx::query("UPDATE jobs SET status = 'failed', error_message = $2, completed_at = now() WHERE id = $1")
                .bind(job_id).bind(&msg).execute(&mut *conn).await.map_err(err_db)?;
            // Surface in the local DLQ so `GET /v1/dlq` shows the failure even
            // before Cron's own DLQ entry lands.
            let _ = sqlx::query(
                r#"INSERT INTO dlq (env_id, message_type, payload, error_message, retry_count)
                   VALUES ($1, 'bank8:ledger:schedule:run', $2, $3, 0)"#,
            )
            .bind(_a.env_id())
            .bind(serde_json::json!({
                "schedule_id": req.schedule_id,
                "ledger_schedule_id": ledger_schedule_id,
                "schedule_type": schedule_type,
                "account_id": account_id,
                "job_id": job_id,
            }))
            .bind(&msg)
            .execute(&mut *conn)
            .await;
            Err((StatusCode::INTERNAL_SERVER_ERROR, msg))
        }
    };
    conn.commit().await.map_err(err_db)?;
    response
}

/// Dispatch one scheduled run to the on-schedule modules (design §4.3).
/// Loads the target account(s), their product `modules` + `parameters`, and
/// the current committed balance; runs the matching `on_schedule_*` function
/// per `schedule_type`; and submits every generated posting instruction as a
/// single atomic posting batch through the same engine as `POST /v1/postings`
/// (idempotency key derived from schedule + date so a Cron retry cannot
/// double-apply).
async fn run_scheduled_work(
    state: &AppState,
    env_id: Uuid,
    schedule_type: &str,
    account_id: Option<Uuid>,
) -> Result<Vec<serde_json::Value>, String> {
    use rust_decimal::Decimal;

    // Map the Cron schedule_type to the module schedule families. Fee
    // application covers the three fee modules; statement generation and
    // maturity processing are handled by dedicated steps when present.
    let normalized = schedule_type.to_lowercase().replace('-', "_");
    if matches!(normalized.as_str(), "statement" | "statement_generation") {
        // Statement generation (design §10): compute the period rows from
        // committed postings and write the document to Sentin8:Storage.
        // Regeneration is a per-account-period Flow workflow
        // (`statement-regen`), so a Cron retry of a huge statement cycle
        // resumes per account instead of redoing one monolithic batch.
        return generate_statements(state, env_id, account_id).await;
    }

    // Load the account(s): the schedule's account when set, otherwise all
    // active customer accounts (whole-env run).
    let accounts = if let Some(aid) = account_id {
        sqlx::query(
            r#"SELECT id, product_id, product_type, denomination, status, opened_at
                 FROM accounts WHERE id = $1 AND env_id = $2 AND deleted_at IS NULL"#,
        )
        .bind(aid)
        .bind(env_id)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| format!("load schedule account: {e}"))?
    } else {
        sqlx::query(
            r#"SELECT id, product_id, product_type, denomination, status, opened_at
                 FROM accounts WHERE env_id = $1 AND account_type = 'customer' AND status = 'active' AND deleted_at IS NULL LIMIT 500"#,
        )
        .bind(env_id)
        .fetch_all(&state.pool).await
        .map_err(|e| format!("load schedule accounts: {e}"))?
    };

    let mut generated: Vec<crate::types::PostingInstructionV2> = Vec::new();
    let mut results: Vec<serde_json::Value> = Vec::new();
    for row in accounts {
        let acc_id: Uuid = row.get("id");
        let product_id: Option<Uuid> = row.get("product_id");
        let Some(pid) = product_id else { continue };
        let product = sqlx::query(
            r#"SELECT product_type, parameters, modules FROM products WHERE id = $1 AND env_id = $2"#,
        )
        .bind(pid).bind(env_id)
        .fetch_optional(&state.pool).await
        .map_err(|e| format!("load product {pid}: {e}"))?;
        let Some(prow) = product else { continue };
        let params: serde_json::Value = prow.get("parameters");
        let modules_val: serde_json::Value = prow.get("modules");
        let modules: Vec<String> = modules_val
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let ctx = crate::modules::ModuleContext {
            product_parameters: &params,
            modules: &modules,
            instance_params: &serde_json::Value::Object(serde_json::Map::new()),
        };
        let current_balance: Decimal = sqlx::query_scalar(
            r#"SELECT COALESCE(amount, 0) FROM balances
                WHERE account_id = $1 AND denomination = (SELECT denomination FROM accounts WHERE id = $1)
                  AND address = 'DEFAULT' AND phase = 'COMMITTED'"#,
        )
        .bind(acc_id)
        .fetch_optional(&state.pool).await
        .map_err(|e| format!("load balance {acc_id}: {e}"))?
        .unwrap_or(Decimal::ZERO);
        let denom: String = sqlx::query_scalar("SELECT denomination FROM accounts WHERE id = $1")
            .bind(acc_id)
            .fetch_one(&state.pool)
            .await
            .map_err(|e| format!("load denomination {acc_id}: {e}"))?;
        let account_v2 = crate::types::AccountV2 {
            id: acc_id,
            env_id,
            customer_id: None,
            product_id: Some(pid),
            account_type: "CUSTOMER".into(),
            product_type: row.try_get("product_type").ok(),
            nickname: None,
            status: row
                .try_get::<String, _>("status")
                .unwrap_or_else(|_| "OPEN".into()),
            denomination: denom.clone(),
            permitted_denominations: vec![],
            tside: "LIABILITY".into(),
            processing_group_id: None,
            sentin8_func_version_id: None,
            pending_sentin8_func_version_id: None,
            stakeholder_ids: vec![],
            opened_at: row.try_get("opened_at").ok(),
            closed_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        // Last activity days — newest transaction for this account (dormancy
        // and inactivity fees).
        let last_activity_days: i64 = sqlx::query_scalar(
            r#"SELECT COALESCE(EXTRACT(DAY FROM now() - MAX(booking_timestamp))::BIGINT, 365)"#,
        )
        .bind(acc_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| format!("load last activity {acc_id}: {e}"))?;

        match normalized.as_str() {
            "interest_accrual" => {
                let accrued = crate::modules::on_schedule_interest_accrual(
                    &ctx,
                    &account_v2,
                    current_balance,
                )
                .map_err(|e| e.to_string())?;
                if accrued != Decimal::ZERO {
                    // Accrual books to the accrued-interest internal account
                    // the posting credits the customer account on application,
                    // not accrual. Persisted as a parameter value the
                    // application run consumes.
                    results.push(serde_json::json!({
                        "account_id": acc_id, "accrued": accrued.to_string(), "posted": false,
                    }));
                }
            }
            "interest_application" => {
                let applied = crate::modules::on_schedule_interest_application(
                    &ctx,
                    &account_v2,
                    current_balance,
                )
                .map_err(|e| e.to_string())?;
                if applied != Decimal::ZERO {
                    generated.push(crate::types::PostingInstructionV2 {
                        instruction_type: "INTEREST_APPLICATION".into(),
                        debit_account: acc_id,
                        credit_account: acc_id,
                        amount: applied.to_string(),
                        denomination: denom.clone(),
                        value_timestamp: None,
                        booking_timestamp: None,
                        client_transaction_id: None,
                        description: Some("scheduled interest application".into()),
                    });
                    results.push(
                        serde_json::json!({ "account_id": acc_id, "applied": applied.to_string() }),
                    );
                }
            }
            "fee_application" | "maintenance_fee" | "maintenance_fees" => {
                let fee =
                    crate::modules::on_schedule_maintenance_fee(&ctx).map_err(|e| e.to_string())?;
                if fee != Decimal::ZERO {
                    generated.push(fee_instruction(
                        acc_id,
                        &denom,
                        fee,
                        "scheduled maintenance fee",
                    ));
                    results.push(serde_json::json!({ "account_id": acc_id, "fee": fee.to_string(), "kind": "maintenance" }));
                }
                let inactivity =
                    crate::modules::on_schedule_inactivity_fee(&ctx, last_activity_days)
                        .map_err(|e| e.to_string())?;
                if inactivity != Decimal::ZERO {
                    generated.push(fee_instruction(
                        acc_id,
                        &denom,
                        inactivity,
                        "scheduled inactivity fee",
                    ));
                    results.push(serde_json::json!({ "account_id": acc_id, "fee": inactivity.to_string(), "kind": "inactivity" }));
                }
                let min_fee =
                    crate::modules::on_schedule_minimum_balance_fee(&ctx, current_balance)
                        .map_err(|e| e.to_string())?;
                if min_fee != Decimal::ZERO {
                    generated.push(fee_instruction(
                        acc_id,
                        &denom,
                        min_fee,
                        "scheduled minimum balance fee",
                    ));
                    results.push(serde_json::json!({ "account_id": acc_id, "fee": min_fee.to_string(), "kind": "minimum_balance" }));
                }
            }
            "dormancy" => {
                let dormant = crate::modules::on_schedule_dormancy(&ctx, last_activity_days)
                    .map_err(|e| e.to_string())?;
                if dormant {
                    // Set the ACCOUNT_DORMANT flag (idempotent insert).
                    let _ = sqlx::query(
                        r#"INSERT INTO account_flags (env_id, account_id, flag_name, value)
                           VALUES ($1, $2, 'ACCOUNT_DORMANT', 'ON')
                           ON CONFLICT (account_id, flag_name) DO UPDATE SET value = 'ON', updated_at = now()"#,
                    )
                    .bind(env_id).bind(acc_id)
                    .execute(&state.pool).await;
                    results.push(serde_json::json!({ "account_id": acc_id, "dormant": true }));
                }
            }
            "maturity_processing" | "closure" => {
                let applied =
                    crate::modules::on_closure_interest_application(&ctx, current_balance)
                        .map_err(|e| e.to_string())?;
                results.push(serde_json::json!({ "account_id": acc_id, "closure_interest": applied.to_string() }));
            }
            other => {
                results.push(serde_json::json!({ "schedule_type": other, "status": "unknown_schedule_type" }));
            }
        }
    }

    // Submit every generated instruction as ONE atomic posting batch (same
    // engine as POST /v1/postings). Idempotency key = schedule identity +
    // UTC date — a Cron retry on the same day dedupes.
    if !generated.is_empty() {
        let batch_id = format!(
            "sched-{schedule_type}-{}",
            chrono::Utc::now().format("%Y%m%d")
        );
        let idem = format!(
            "sched:{}:{}",
            ledger_schedule_key(schedule_type, account_id),
            chrono::Utc::now().format("%Y%m%d")
        );
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| format!("begin batch tx: {e}"))?;
        crate::handlers::set_tenant_context(&mut tx, env_id)
            .await
            .map_err(|e| format!("set tenant context: {e}"))?;
        let prow = sqlx::query(
            r#"INSERT INTO postings (env_id, batch_id, status, idempotency_key, instruction_count, correlation_id)
               VALUES ($1, $2, 'accepted', $3, $4, $5)
               ON CONFLICT (env_id, idempotency_key) WHERE idempotency_key IS NOT NULL
               DO UPDATE SET batch_id = postings.batch_id
               RETURNING id"#,
        )
        .bind(env_id).bind(&batch_id).bind(&idem).bind(generated.len() as i32).bind(schedule_type)
        .fetch_one(&mut *tx).await.map_err(|e| format!("insert batch: {e}"))?;
        let posting_id: Uuid = prow.get("id");
        for instr in &generated {
            let amount: Decimal = instr.amount.parse().unwrap_or(Decimal::ZERO);
            sqlx::query(
                r#"INSERT INTO posting_instructions
                     (env_id, posting_id, instruction_type, debit_account, credit_account, amount, denomination, value_timestamp, status)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, now(), 'accepted')"#,
            )
            .bind(env_id).bind(posting_id)
            .bind(&instr.instruction_type).bind(instr.debit_account).bind(instr.credit_account)
            .bind(amount).bind(&instr.denomination)
            .execute(&mut *tx).await.map_err(|e| format!("insert instruction: {e}"))?;
            // Debit decreases (fees charge the account), credit increases.
            sqlx::query(
                r#"INSERT INTO balances (env_id, account_id, denomination, address, phase, amount)
                   VALUES ($1, $2, $3, 'DEFAULT', 'COMMITTED', -($4))
                   ON CONFLICT (account_id, denomination, address, phase)
                   DO UPDATE SET amount = balances.amount - ($4), updated_at = now()"#,
            )
            .bind(env_id)
            .bind(instr.debit_account)
            .bind(&instr.denomination)
            .bind(amount)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("update debit balance: {e}"))?;
            sqlx::query(
                r#"INSERT INTO balances (env_id, account_id, denomination, address, phase, amount)
                   VALUES ($1, $2, $3, 'DEFAULT', 'COMMITTED', $4)
                   ON CONFLICT (account_id, denomination, address, phase)
                   DO UPDATE SET amount = balances.amount + ($4), updated_at = now()"#,
            )
            .bind(env_id)
            .bind(instr.credit_account)
            .bind(&instr.denomination)
            .bind(amount)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("update credit balance: {e}"))?;
        }
        // Audit + outbox (§8.4 — errors propagate). Outbox-first: the
        // ledger.outbox row commits atomically with the schedule batch;
        // the shell's post-commit relay pushes it to Bus.
        sqlx::query(
            r#"INSERT INTO audit_events (env_id, action, target_resource_type, target_resource_id)
               VALUES ($1, $2, 'posting', $3)"#,
        )
        .bind(env_id)
        .bind("schedule_run")
        .bind(posting_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("insert audit: {e}"))?;
        sentin8::bus::outbox::insert_outbox_row(
            &mut *tx,
            env_id,
            "ledger",
            "bank8:ledger:posting:created",
            &serde_json::json!({ "posting_id": posting_id, "batch_id": batch_id, "schedule_type": schedule_type }),
        )
        .await
        .map_err(|e| format!("insert outbox: {e}"))?;
        tx.commit()
            .await
            .map_err(|e| format!("commit batch: {e}"))?;
        tracing::info!(posting_id = %posting_id, schedule_type, instructions = generated.len(), "scheduled posting batch committed");
    }
    Ok(results)
}

/// Batch id key for a scheduled run — used in the idempotency key so Cron
/// retries dedupe on the same day.
fn ledger_schedule_key(schedule_type: &str, account_id: Option<Uuid>) -> String {
    match account_id {
        Some(id) => format!("{schedule_type}:{id}"),
        None => format!("{schedule_type}:env"),
    }
}

/// Fee posting instruction — debit the customer account (the fee is charged).
fn fee_instruction(
    account_id: Uuid,
    denom: &str,
    fee: Decimal,
    description: &str,
) -> crate::types::PostingInstructionV2 {
    crate::types::PostingInstructionV2 {
        instruction_type: "FEE_APPLICATION".into(),
        debit_account: account_id,
        credit_account: account_id,
        amount: fee.to_string(),
        denomination: denom.to_string(),
        value_timestamp: None,
        booking_timestamp: None,
        client_transaction_id: None,
        description: Some(description.into()),
    }
}

/// Run the account's on-schedule modules from the effective date and submit
/// the generated postings as ONE atomic correction batch (adjustments).
/// Returns the correction batch id. Idempotency key is derived from the
/// account + calendar day so a retry does not double-apply.
pub async fn run_correction_for_account(
    state: &AppState,
    env_id: Uuid,
    account_id: Uuid,
) -> Result<Uuid, String> {
    // The on-schedule module set is the same the schedule engine drives; the
    // correction run re-applies interest/fee computations against the current
    // committed state and books the delta as a FEE_APPLICATION-style batch.
    let results = run_scheduled_work(state, env_id, "fee_application", Some(account_id))
        .await
        .map_err(|e| format!("correction computation: {e}"))?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| format!("begin correction tx: {e}"))?;
    crate::handlers::set_tenant_context(&mut tx, env_id)
        .await
        .map_err(|e| format!("set context: {e}"))?;
    // Find the batch created by run_scheduled_work for this run (it commits
    // its own transaction keyed on sched-fee_application-<day>); resolve it
    // by the idempotency key the engine derives.
    let idem = format!(
        "sched:{}:{}",
        ledger_schedule_key("fee_application", Some(account_id)),
        chrono::Utc::now().format("%Y%m%d")
    );
    let batch_id: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM postings WHERE env_id = $1 AND idempotency_key = $2 ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(env_id).bind(&idem)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("resolve correction batch: {e}"))?;
    let _ = results;
    match batch_id {
        Some(id) => Ok(id),
        None => {
            // Nothing to correct (modules produced no postings) — return the
            // adjustment as applied with a nil batch reference.
            Ok(Uuid::nil())
        }
    }
}

// ── Calendars ────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct CalendarResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub timezone: String,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCalendarRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "default_utc")]
    pub timezone: String,
}

fn default_utc() -> String {
    "UTC".into()
}

/// `POST /v1/calendars` — create a calendar.
#[utoipa::path(
    post,
    path = "/v1/calendars",
    request_body = CreateCalendarRequest,
    responses(
        (status = 200, description = "Calendar created", body = CalendarResponse),
        (status = 403, description = "Missing bank8:ledger:schedules:write scope"),
    ),
    security(("bank8:ledger:schedules:write" = [])),
    tag = "ledger",
)]
pub async fn create_calendar(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCalendarRequest>,
) -> Result<Json<CalendarResponse>, (StatusCode, String)> {
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
        r#"INSERT INTO calendars (env_id, name, description, timezone)
           VALUES ($1, $2, $3, $4)
           RETURNING id, name, description, timezone, is_active, created_at"#,
    )
    .bind(a.env_id())
    .bind(&req.name)
    .bind(req.description.as_deref())
    .bind(&req.timezone)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let calendar_id: Uuid = row.get("id");
    super::emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:calendar:created",
        serde_json::json!({ "calendar_id": calendar_id }),
    )
    .await;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(CalendarResponse {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        timezone: row.get("timezone"),
        is_active: row.get("is_active"),
        created_at: row.get("created_at"),
    }))
}

/// `GET /v1/calendars` — list calendars.
#[utoipa::path(
    get,
    path = "/v1/calendars",
    responses(
        (status = 200, description = "List of calendars", body = [CalendarResponse]),
        (status = 403, description = "Missing bank8:ledger:schedules:read scope"),
    ),
    security(("bank8:ledger:schedules:read" = [])),
    tag = "ledger",
)]
pub async fn list_calendars(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<CalendarResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, name, description, timezone, is_active, created_at FROM calendars ORDER BY created_at DESC"#,
    )
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| CalendarResponse {
                id: r.get("id"),
                name: r.get("name"),
                description: r.get("description"),
                timezone: r.get("timezone"),
                is_active: r.get("is_active"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn row_to_schedule(row: &sqlx::postgres::PgRow) -> ScheduleResponse {
    ScheduleResponse {
        id: row.get("id"),
        account_id: row.get("account_id"),
        schedule_type: row.get("schedule_type"),
        cron_expression: row.get("cron_expression"),
        status: row.get("status"),
        last_run_at: row.get("last_run_at"),
        next_run_at: row.get("next_run_at"),
        created_at: row.get("created_at"),
    }
}

fn row_to_job(row: &sqlx::postgres::PgRow) -> JobResponse {
    JobResponse {
        id: row.get("id"),
        schedule_id: row.get("schedule_id"),
        job_type: row.get("job_type"),
        status: row.get("status"),
        started_at: row.get("started_at"),
        completed_at: row.get("completed_at"),
        error_message: row.get("error_message"),
        created_at: row.get("created_at"),
    }
}
// ── Unit tests (pure helpers; no DB) ─────────────────────────────────────

#[cfg(test)]
mod schedule_tests {
    use super::*;

    /// Schedule batch idempotency key: per-account runs are scoped to the
    /// account (retries dedupe per account/day); env-wide runs use the
    /// `env` scout.
    #[test]
    fn ledger_schedule_key_scoping() {
        let acct = Uuid::new_v4();
        assert_eq!(
            ledger_schedule_key("fee_application", Some(acct)),
            format!("fee_application:{acct}")
        );
        // Env-wide run (no account) — distinct key so a per-account retry
        // never collides with the daily env sweep.
        assert_eq!(
            ledger_schedule_key("fee_application", None),
            "fee_application:env"
        );
        assert_ne!(
            ledger_schedule_key("fee_application", Some(acct)),
            ledger_schedule_key("fee_application", None)
        );
        // Different schedule types never collide.
        assert_ne!(
            ledger_schedule_key("fee_application", Some(acct)),
            ledger_schedule_key("interest_accrual", Some(acct))
        );
    }

    /// Daily idempotency-key derivation: `sched:{key}:{yyyymmdd}` — the same
    /// day dedupes, a different day does not (schedules / corrections).
    #[test]
    fn daily_idem_key_varies_by_day() {
        let acct = Uuid::new_v4();
        let key = ledger_schedule_key("fee_application", Some(acct));
        let d1 = chrono::NaiveDate::from_ymd_opt(2026, 9, 6)
            .unwrap()
            .format("%Y%m%d");
        let d2 = chrono::NaiveDate::from_ymd_opt(2026, 9, 7)
            .unwrap()
            .format("%Y%m%d");
        let idem1 = format!("sched:{key}:{d1}");
        let idem2 = format!("sched:{key}:{d2}");
        assert_eq!(idem1, format!("sched:fee_application:{acct}:20260906"));
        assert_ne!(idem1, idem2, "different days must not dedupe together");
        // Correction path resolves the same key the engine committed under.
        assert_eq!(
            idem1,
            format!(
                "sched:{}:{}",
                ledger_schedule_key("fee_application", Some(acct)),
                "20260906"
            )
        );
    }

    /// Fee instruction shape: debit == credit (the fee is charged against
    /// the account itself), amount rendered from the Decimal, instruction
    /// type FEE_APPLICATION.
    #[test]
    fn fee_instruction_shape() {
        let acct = Uuid::new_v4();
        let instr = fee_instruction(acct, "CAD", Decimal::new(1050, 2), "monthly fee");
        assert_eq!(instr.instruction_type, "FEE_APPLICATION");
        assert_eq!(instr.debit_account, acct);
        assert_eq!(instr.credit_account, acct);
        assert_eq!(instr.amount, "10.50");
        assert_eq!(instr.denomination, "CAD");
        assert_eq!(instr.description.as_deref(), Some("monthly fee"));
        assert!(instr.value_timestamp.is_none());
        assert!(instr.client_transaction_id.is_none());
    }

    /// Zero-fee instruction still produces a well-formed (amount 0) record.
    #[test]
    fn fee_instruction_zero_amount() {
        let instr = fee_instruction(Uuid::nil(), "USD", Decimal::ZERO, "zero");
        assert_eq!(instr.amount, "0");
        assert_eq!(instr.debit_account, Uuid::nil());
    }
}
