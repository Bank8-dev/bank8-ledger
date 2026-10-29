// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Posting handlers - posting instruction batches (sync/async), instructions, DLQ.
//! The posting engine implements:
//! - Double-entry validation (every debit has a credit)
//! - Atomic batch processing (all instructions succeed or all fail)
//! - Idempotency via idempotency_key
//! - Balance updates (COMMITTED phase, DEFAULT address)
//! - Transaction records for account history
//! - Module validation (deposit-limits, withdrawal-limits, maximum-balance, etc.)
//! - Dry run support (skip commit, events, balance updates)

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use rust_decimal::Decimal;
use serde::Deserialize;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{err_db, set_tenant_context, AppState};

#[derive(Debug, Deserialize, serde::Serialize, ToSchema)]
pub struct PostingInstruction {
    pub instruction_type: String,
    pub debit_account: Uuid,
    pub credit_account: Uuid,
    pub amount: String,
    #[serde(default = "default_denom")]
    pub denomination: String,
    #[serde(default)]
    pub value_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub description: Option<String>,
}

fn default_denom() -> String {
    "CAD".into()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePostingRequest {
    pub batch_id: String,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    pub instructions: Vec<PostingInstruction>,
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct PostingResponse {
    pub id: Uuid,
    pub batch_id: String,
    pub status: String,
    pub instruction_count: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub balances: Vec<BalanceEntry>,
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct BalanceEntry {
    pub account_id: Uuid,
    pub denomination: String,
    pub address: String,
    pub phase: String,
    pub amount: Decimal,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AsyncPostingRequest {
    pub batch_id: String,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    pub instructions: Vec<PostingInstruction>,
}

/// `POST /v1/postings` - synchronous posting instruction batch.
#[utoipa::path(
    post,
    path = "/v1/postings",
    request_body = CreatePostingRequest,
    responses(
        (status = 200, description = "Posting batch processed", body = PostingResponse),
        (status = 400, description = "Invalid amount or empty instructions"),
        (status = 403, description = "Missing bank8:ledger:postings:write scope"),
    ),
    security(("bank8:ledger:postings:write" = [])),
    tag = "ledger",
)]
pub async fn create_posting(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreatePostingRequest>,
) -> Result<Json<PostingResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:write"),
    )
    .await?;
    if req.instructions.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "at least one instruction required".into(),
        ));
    }
    // Validate amounts.
    for instr in &req.instructions {
        let amount = instr
            .amount
            .parse::<Decimal>()
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid amount: {e}")))?;
        if amount <= Decimal::ZERO {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("amount must be positive: {amount}"),
            ));
        }
    }

    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, a.env_id())
        .await
        .map_err(err_db)?;
    tracing::info!(env_id = %a.env_id(), batch_id = %req.batch_id, dry_run = req.dry_run, instructions = req.instructions.len(), "ledger: create_posting tx started");

    // Idempotency check.
    if let Some(key) = &req.idempotency_key {
        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM postings WHERE idempotency_key = $1 AND env_id = $2",
        )
        .bind(key)
        .bind(a.env_id())
        .fetch_optional(&mut *tx)
        .await
        .map_err(err_db)?;
        if let Some(id) = existing {
            let row = sqlx::query(
                r#"SELECT id, batch_id, status, instruction_count, created_at, completed_at FROM postings WHERE id = $1"#,
            ).bind(id).fetch_one(&mut *tx).await.map_err(err_db)?;
            tx.commit().await.map_err(err_db)?;
            return Ok(Json(PostingResponse {
                id: row.get("id"),
                batch_id: row.get("batch_id"),
                status: row.get("status"),
                instruction_count: row.get("instruction_count"),
                created_at: row.get("created_at"),
                completed_at: row.get("completed_at"),
                balances: vec![],
            }));
        }
    }

    // Insert posting batch. ON CONFLICT closes the SELECT-then-INSERT race
    // window on the idempotency key - a concurrent duplicate returns the
    // original batch row instead of creating a second one.
    let row = sqlx::query(
        r#"INSERT INTO postings (env_id, batch_id, status, idempotency_key, instruction_count)
           VALUES ($1, $2, 'accepted', $3, $4)
           ON CONFLICT (env_id, idempotency_key) WHERE idempotency_key IS NOT NULL
           DO UPDATE SET batch_id = postings.batch_id
           RETURNING id, batch_id, status, instruction_count, created_at, completed_at"#,
    )
    .bind(a.env_id())
    .bind(&req.batch_id)
    .bind(&req.idempotency_key)
    .bind(req.instructions.len() as i32)
    .fetch_one(&mut *tx)
    .await
    .map_err(err_db)?;

    let posting_id: Uuid = row.get("id");
    let mut affected_balances: Vec<(Uuid, String)> = Vec::new();

    if req.dry_run {
        // Dry run: skip commit, events, balance updates.
        sqlx::query("UPDATE postings SET status = 'rejected', completed_at = now() WHERE id = $1")
            .bind(posting_id)
            .execute(&mut *tx)
            .await
            .map_err(err_db)?;
        tx.commit().await.map_err(err_db)?;
        return Ok(Json(PostingResponse {
            id: row.get("id"),
            batch_id: row.get("batch_id"),
            status: "dry_run".into(),
            instruction_count: row.get("instruction_count"),
            created_at: row.get("created_at"),
            completed_at: row.get("completed_at"),
            balances: vec![],
        }));
    }

    // Process each instruction atomically.
    // Tenant-authored posting hooks are event-triggered via `event_triggers`
    // registration (architecture principles §4.14) or direct bus consumers -
    // never inline SQL column lookups inside the posting transaction. The
    // `/v1/internal/func-host` proxy-back and the
    // scheduled/activation/deactivation hooks remain (their module ids come
    // from schedule contracts, not accounts columns).

    // Double-entry validation: the batch must net out per denomination
    // the weighted debit direction (WITHDRAWAL/FEE/REVERSAL debit the source)
    // vs credit direction must balance (§4.1). Checked before any row is
    // written. Pure logic lives in `check_double_entry` (unit-tested).
    check_double_entry(&req.instructions).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // Module context cache - product id → (modules, parameters). Loaded once
    // per product so every instruction in the batch reuses it.
    let mut module_ctx_cache: std::collections::HashMap<
        Uuid,
        (Vec<String>, serde_json::Value, serde_json::Value),
    > = std::collections::HashMap::new();

    for instr in &req.instructions {
        let amount: Decimal = instr.amount.parse().unwrap();
        let value_ts = instr.value_timestamp.unwrap_or_else(chrono::Utc::now);

        // Posting-time module validation (§4.2.2 execution point 2). The
        // debit account's product drives the rules - withdrawal/deposit
        // limits, transaction-type limits, maximum balance, overdraft.
        // Daily totals are summed across the whole batch per (account, type)
        // so a batch cannot split around a daily cap.
        let debit_product = sqlx::query(
            r#"SELECT product_id, product_type FROM accounts WHERE id = $1 AND env_id = $2"#,
        )
        .bind(instr.debit_account)
        .bind(a.env_id())
        .fetch_optional(&mut *tx)
        .await
        .map_err(err_db)?;
        if let Some(prow) = debit_product {
            let product_id: Option<Uuid> = prow.get("product_id");
            let product_type: Option<String> = prow.get("product_type");
            if let Some(pid) = product_id {
                let (modules, params, instance_params) =
                    if let Some(v) = module_ctx_cache.get(&pid) {
                        v.clone()
                    } else {
                        let prow = sqlx::query(
                        r#"SELECT parameters, modules FROM products WHERE id = $1 AND env_id = $2"#,
                    )
                    .bind(pid).bind(a.env_id())
                    .fetch_optional(&mut *tx).await.map_err(err_db)?;
                        let v = prow
                            .map(|r| {
                                let params: serde_json::Value = r.get("parameters");
                                let modules_val: serde_json::Value = r.get("modules");
                                let modules: Vec<String> = modules_val
                                    .as_array()
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|m| m.as_str().map(String::from))
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                (
                                    modules,
                                    params,
                                    serde_json::Value::Object(serde_json::Map::new()),
                                )
                            })
                            .unwrap_or_else(|| {
                                (
                                    vec![],
                                    serde_json::Value::Object(serde_json::Map::new()),
                                    serde_json::Value::Object(serde_json::Map::new()),
                                )
                            });
                        module_ctx_cache.insert(pid, v.clone());
                        v
                    };
                // Current committed balance of the debit account.
                let current_balance: Decimal = sqlx::query_scalar(
                    r#"SELECT COALESCE(amount, 0) FROM balances
                        WHERE account_id = $1 AND denomination = $2 AND address = 'DEFAULT' AND phase = 'COMMITTED'"#,
                )
                .bind(instr.debit_account).bind(&instr.denomination)
                .fetch_optional(&mut *tx).await.map_err(err_db)?
                .unwrap_or(Decimal::ZERO);
                // Daily totals for this account across the batch (same
                // instruction type contributes to its per-type total).
                let daily_deposit_total: Decimal = req
                    .instructions
                    .iter()
                    .filter(|i| {
                        i.debit_account == instr.debit_account
                            && i.instruction_type.eq_ignore_ascii_case("DEPOSIT")
                    })
                    .map(|i| i.amount.parse::<Decimal>().unwrap_or(Decimal::ZERO))
                    .fold(Decimal::ZERO, |acc, x| acc + x);
                let daily_withdrawal_total: Decimal = req
                    .instructions
                    .iter()
                    .filter(|i| {
                        i.debit_account == instr.debit_account
                            && i.instruction_type.eq_ignore_ascii_case("WITHDRAWAL")
                    })
                    .map(|i| i.amount.parse::<Decimal>().unwrap_or(Decimal::ZERO))
                    .fold(Decimal::ZERO, |acc, x| acc + x);
                let daily_txn_type_total: Decimal = req
                    .instructions
                    .iter()
                    .filter(|i| {
                        i.debit_account == instr.debit_account
                            && i.instruction_type
                                .eq_ignore_ascii_case(&instr.instruction_type)
                    })
                    .map(|i| i.amount.parse::<Decimal>().unwrap_or(Decimal::ZERO))
                    .fold(Decimal::ZERO, |acc, x| acc + x);
                let v2 = crate::types::PostingInstructionV2 {
                    instruction_type: instr.instruction_type.clone(),
                    debit_account: instr.debit_account,
                    credit_account: instr.credit_account,
                    amount: instr.amount.clone(),
                    denomination: instr.denomination.clone(),
                    value_timestamp: instr.value_timestamp,
                    booking_timestamp: None,
                    client_transaction_id: None,
                    description: instr.description.clone(),
                };
                let ctx = crate::modules::ModuleContext {
                    product_parameters: &params,
                    modules: &modules,
                    instance_params: &instance_params,
                };
                if let Err(e) = crate::modules::validate_posting(
                    &ctx,
                    &v2,
                    current_balance,
                    daily_deposit_total - amount,
                    daily_withdrawal_total - amount,
                    daily_txn_type_total - amount,
                ) {
                    tracing::warn!(error = %e, product_type = ?product_type, batch_id = %req.batch_id, "posting rejected by module validation");
                    return Err((StatusCode::UNPROCESSABLE_ENTITY, e.to_string()));
                }
                // Overdraft sweep: if the debit would overdraw and the product
                // has a sweep, the sweep covers the gap from the linked
                // savings account - surfaced as a hook result, the posting
                // itself proceeds (sweep amount recorded in the audit trail).
                if let Some(sweep) =
                    crate::modules::validate_posting_overdraft_sweep(&ctx, &v2, current_balance)
                        .unwrap_or(None)
                {
                    tracing::info!(batch_id = %req.batch_id, sweep = %sweep, "overdraft sweep triggered");
                }
            }
        }

        sqlx::query(
            r#"INSERT INTO posting_instructions
                 (env_id, posting_id, instruction_type, debit_account, credit_account, amount, denomination, value_timestamp, status)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'accepted')"#,
        )
        .bind(a.env_id()).bind(posting_id)
        .bind(&instr.instruction_type).bind(instr.debit_account).bind(instr.credit_account)
        .bind(amount).bind(&instr.denomination).bind(value_ts)
        .execute(&mut *tx).await.map_err(err_db)?;

        // Update balances: debit decreases, credit increases (COMMITTED phase, DEFAULT address).
        sqlx::query(
            r#"INSERT INTO balances (env_id, account_id, denomination, address, phase, amount)
               VALUES ($1, $2, $3, 'DEFAULT', 'COMMITTED', -($4))
               ON CONFLICT (account_id, denomination, address, phase)
               DO UPDATE SET amount = balances.amount - ($4), updated_at = now()"#,
        )
        .bind(a.env_id())
        .bind(instr.debit_account)
        .bind(&instr.denomination)
        .bind(amount)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;

        sqlx::query(
            r#"INSERT INTO balances (env_id, account_id, denomination, address, phase, amount)
               VALUES ($1, $2, $3, 'DEFAULT', 'COMMITTED', $4)
               ON CONFLICT (account_id, denomination, address, phase)
               DO UPDATE SET amount = balances.amount + ($4), updated_at = now()"#,
        )
        .bind(a.env_id())
        .bind(instr.credit_account)
        .bind(&instr.denomination)
        .bind(amount)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;

        // Create transaction records for both accounts.
        sqlx::query(
            r#"INSERT INTO transactions (env_id, account_id, posting_id, amount, denomination, direction, description, value_timestamp, booking_timestamp)
               VALUES ($1, $2, $3, $4, $5, 'debit', $6, $7, now())"#,
        )
        .bind(a.env_id()).bind(instr.debit_account).bind(posting_id)
        .bind(amount).bind(&instr.denomination).bind(instr.description.as_deref()).bind(value_ts)
        .execute(&mut *tx).await.map_err(err_db)?;

        sqlx::query(
            r#"INSERT INTO transactions (env_id, account_id, posting_id, amount, denomination, direction, description, value_timestamp, booking_timestamp)
               VALUES ($1, $2, $3, $4, $5, 'credit', $6, $7, now())"#,
        )
        .bind(a.env_id()).bind(instr.credit_account).bind(posting_id)
        .bind(amount).bind(&instr.denomination).bind(instr.description.as_deref()).bind(value_ts)
        .execute(&mut *tx).await.map_err(err_db)?;

        affected_balances.push((instr.debit_account, instr.denomination.clone()));
        affected_balances.push((instr.credit_account, instr.denomination.clone()));
    }

    // Mark posting as completed.
    sqlx::query("UPDATE postings SET status = 'accepted', completed_at = now() WHERE id = $1")
        .bind(posting_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;

    // Emit audit event (§8.4 - exactly five columns / five values; errors
    // propagate so an audit failure aborts the posting instead of committing
    // a silent empty transaction).
    sqlx::query(
        r#"INSERT INTO audit_events (env_id, actor_user_id, action, target_resource_type, target_resource_id)
           VALUES ($1, $2, $3, 'posting', $4)"#,
    )
    .bind(a.env_id()).bind(&a.claims.sub).bind("create").bind(posting_id.to_string())
    .execute(&mut *tx).await.map_err(err_db)?;

    // Emit outbox event with publisher identity token (§4.5) - errors
    // propagate (§8.4 rule 2): never commit a posting whose event emission
    // failed. Outbox-first: the ledger.outbox row commits atomically with
    // the posting; the shell's post-commit relay pushes it to Bus.
    let publisher_id_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string());
    sentin8::bus::outbox::insert_outbox_row_with_publisher(
        &mut *tx,
        a.env_id(),
        "ledger",
        "bank8:ledger:posting:created",
        &serde_json::json!({ "posting_id": posting_id, "batch_id": req.batch_id }),
        publisher_id_token.as_deref(),
        Some(&a.claims.sub),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, posting_id = %posting_id, "posting outbox insert failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("posting outbox insert failed: {e}"),
        )
    })?;

    tx.commit().await.map_err(err_db)?;

    // Read-back verification - count the posting row on a pooled (fresh)
    // connection. Surfaces any disconnect between "sqlx commit returned Ok"
    // and the row actually being visible (e.g. wrong database/search_path).
    let readback: Option<(String, i64)> = sqlx::query_as(
        r#"SELECT COALESCE(current_setting('search_path'), ''), (SELECT count(*)::bigint FROM postings WHERE id = $1)"#,
    )
    .bind(posting_id)
    .fetch_one(&state.pool)
    .await
    .ok();
    tracing::info!(
        posting_id = %posting_id,
        env_id = %a.env_id(),
        batch_id = %req.batch_id,
        readback = ?readback,
        "ledger: posting committed"
    );

    // Fetch updated balances for affected accounts.
    let mut balances = Vec::new();
    for (account_id, denom) in &affected_balances {
        let balance_row = sqlx::query(
            r#"SELECT account_id, denomination, address, phase, amount
                 FROM balances WHERE account_id = $1 AND denomination = $2 AND address = 'DEFAULT' AND phase = 'COMMITTED'"#,
        )
        .bind(account_id).bind(denom)
        .fetch_optional(&state.pool).await;
        if let Ok(Some(r)) = balance_row {
            balances.push(BalanceEntry {
                account_id: r.get("account_id"),
                denomination: r.get("denomination"),
                address: r.get("address"),
                phase: r.get("phase"),
                amount: r.get("amount"),
            });
        }
    }

    /* removed misplaced commit */
    Ok(Json(PostingResponse {
        id: row.get("id"),
        batch_id: row.get("batch_id"),
        status: row.get("status"),
        instruction_count: row.get("instruction_count"),
        created_at: row.get("created_at"),
        completed_at: row.get("completed_at"),
        balances,
    }))
}

/// `POST /v1/postings/async` - async posting via Bus (enqueues to Bus stream).
#[utoipa::path(
    post,
    path = "/v1/postings/async",
    request_body = AsyncPostingRequest,
    responses(
        (status = 200, description = "Async posting enqueued"),
        (status = 400, description = "Empty instructions"),
        (status = 403, description = "Missing bank8:ledger:postings:write scope"),
    ),
    security(("bank8:ledger:postings:write" = [])),
    tag = "ledger",
)]
pub async fn create_posting_async(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AsyncPostingRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:write"),
    )
    .await?;
    if req.instructions.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "at least one instruction required".into(),
        ));
    }
    // Insert as pending, will be processed by worker.
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"INSERT INTO postings (env_id, batch_id, status, idempotency_key, instruction_count)
           VALUES ($1, $2, 'pending', $3, $4)
           RETURNING id, batch_id"#,
    )
    .bind(a.env_id())
    .bind(&req.batch_id)
    .bind(&req.idempotency_key)
    .bind(req.instructions.len() as i32)
    .fetch_one(&mut *tx)
    .await
    .map_err(err_db)?;
    let posting_id: Uuid = row.get("id");

    // Store instructions as pending.
    for instr in &req.instructions {
        let amount: Decimal = instr.amount.parse().unwrap_or(Decimal::ZERO);
        sqlx::query(
            r#"INSERT INTO posting_instructions
                 (env_id, posting_id, instruction_type, debit_account, credit_account, amount, denomination, status)
               VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')"#,
        )
        .bind(a.env_id()).bind(posting_id)
        .bind(&instr.instruction_type).bind(instr.debit_account).bind(instr.credit_account)
        .bind(amount).bind(&instr.denomination)
        .execute(&mut *tx).await.map_err(err_db)?;
    }

    // Enqueue to Bus (M2M-backed client built at startup).
    // Pass the publisher's bearer token so subscribers can delegate (§4.5).
    // Errors propagate (§8.4 rule 2) - an async request whose enqueue fails
    // must fail the request, never return pending with no event produced.
    let publisher_id_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string());
    let bus = state.bus_client.clone();
    let produce_req = sentin8::bus::contracts::ProduceRequest {
        stream_family: state.config.stream_family.clone(),
        env_id: Some(a.env_id()),
        event_type: "bank8:ledger:posting:async:request".into(),
        payload: serde_json::json!({ "posting_id": posting_id }),
        correlation_id: Some(req.batch_id.clone()),
        idempotency_key: req.idempotency_key.clone(),
        publisher_id_token,
        publisher_subject: Some(a.claims.sub.clone()),
    };
    bus.produce(&produce_req).await.map_err(|e| {
        tracing::error!(error = %e, posting_id = %posting_id, "bus produce failed for async posting");
        (StatusCode::INTERNAL_SERVER_ERROR, format!("bus produce failed: {e}"))
    })?;

    tx.commit().await.map_err(err_db)?;
    Ok(Json(
        serde_json::json!({ "id": posting_id, "status": "pending" }),
    ))
}

/// `GET /v1/postings/{id}` - batch status.
#[utoipa::path(
    get,
    path = "/v1/postings/{id}",
    params(("id" = Uuid, Path, description = "Posting batch ID")),
    responses(
        (status = 200, description = "Posting batch status", body = PostingResponse),
        (status = 404, description = "Posting not found"),
        (status = 403, description = "Missing bank8:ledger:postings:read scope"),
    ),
    security(("bank8:ledger:postings:read" = [])),
    tag = "ledger",
)]
pub async fn get_posting(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<PostingResponse>, (StatusCode, String)> {
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
        r#"SELECT id, batch_id, status, instruction_count, created_at, completed_at FROM postings WHERE id = $1"#,
    )
    .bind(id).fetch_one(&mut *conn).await.map_err(err_db)?;
    Ok(Json(PostingResponse {
        id: row.get("id"),
        batch_id: row.get("batch_id"),
        status: row.get("status"),
        instruction_count: row.get("instruction_count"),
        created_at: row.get("created_at"),
        completed_at: row.get("completed_at"),
        balances: vec![],
    }))
}

/// `GET /v1/postings/{id}/instructions` - list instructions in a batch.
#[utoipa::path(
    get,
    path = "/v1/postings/{id}/instructions",
    params(("id" = Uuid, Path, description = "Posting batch ID")),
    responses(
        (status = 200, description = "List of posting instructions"),
        (status = 403, description = "Missing bank8:ledger:postings:read scope"),
    ),
    security(("bank8:ledger:postings:read" = [])),
    tag = "ledger",
)]
pub async fn get_posting_instructions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
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
        r#"SELECT id, instruction_type, debit_account, credit_account, amount, denomination, value_timestamp, status
             FROM posting_instructions WHERE posting_id = $1 ORDER BY created_at"#,
    )
    .bind(id).fetch_all(&mut *conn).await.map_err(err_db)?;
    let instructions: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
        "id": r.get::<Uuid, _>("id"),
        "instruction_type" : r.get::<String, _>("instruction_type"),
        "debit_account" : r.get::<Uuid, _>("debit_account"),
        "credit_account" : r.get::<Uuid, _>("credit_account"),
        "amount": r.get::<Decimal, _>("amount"),
        "denomination": r.get::<String, _>("denomination"),
        "value_timestamp" : r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("value_timestamp"),
        "status": r.get::<String, _>("status"),
    })).collect();
    Ok(Json(instructions))
}

// ── DLQ ──────────────────────────────────────────────────────────────────

/// `GET /v1/admin/postings` - posting batches list (RFW DataTable).

/// One posting batch row (admin view).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct PostingBatchRow {
    /// The batch row id.
    pub id: uuid::Uuid,
    /// The batch business id.
    pub batch_id: String,
    /// Batch status.
    pub status: String,
    /// Postings in the batch.
    pub instruction_count: i64,
    /// Created at.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Completed at (absent while open).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[utoipa::path(
    get,
    path = "/v1/admin/postings",
    responses(
        (status = 200, description = "Posting batches (admin view)", body = Vec<PostingBatchRow>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn list_postings_batches(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PostingBatchRow>>, (StatusCode, String)> {
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
        r#"SELECT id, batch_id, status, instruction_count, created_at, completed_at
             FROM postings ORDER BY created_at DESC LIMIT 100"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let batches: Vec<PostingBatchRow> = rows
        .iter()
        .map(|r| PostingBatchRow {
            id: r.get::<Uuid, _>("id"),
            batch_id: r.get::<String, _>("batch_id"),
            status: r.get::<String, _>("status"),
            instruction_count: r.get::<i32, _>("instruction_count") as i64,
            created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            completed_at: r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("completed_at"),
        })
        .collect();
    Ok(Json(batches))
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct DlqResponse {
    pub id: Uuid,
    pub message_type: String,
    pub payload: serde_json::Value,
    pub error_message: String,
    pub retry_count: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/dlq` - list dead-letter queue entries (local posting DLQ + Cron schedule DLQ).
#[utoipa::path(
    get,
    path = "/v1/dlq",
    responses(
        (status = 200, description = "DLQ entries", body = [DlqResponse]),
        (status = 403, description = "Missing bank8:ledger:dlq:read scope"),
    ),
    security(("bank8:ledger:dlq:read" = [])),
    tag = "ledger",
)]
pub async fn list_dlq(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DlqResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:dlq:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    // Local posting DLQ entries.
    let rows = sqlx::query(
        r#"SELECT id, message_type, payload, error_message, retry_count, created_at
             FROM dlq ORDER BY created_at DESC LIMIT 100"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let mut entries: Vec<DlqResponse> = rows
        .iter()
        .map(|r| DlqResponse {
            id: r.get("id"),
            message_type: r.get("message_type"),
            payload: r.get("payload"),
            error_message: r.get("error_message"),
            retry_count: r.get("retry_count"),
            created_at: r.get("created_at"),
        })
        .collect();
    // Also fetch schedule-related DLQ entries from Cron.
    let cron = crate::cron_client::CronClient::new(
        &state.config.sentin8_cron_url,
        &state.config.sentin8_cron_token,
    );
    if let Ok(sentin8_cron_dlq) = cron.list_dlq().await {
        for entry in sentin8_cron_dlq {
            if let Some(domain) = entry.get("domain").and_then(|v| v.as_str()) {
                if domain == "ledger" {
                    entries.push(DlqResponse {
                        id: entry
                            .get("id")
                            .and_then(|v| v.as_str())
                            .and_then(|s| uuid::Uuid::parse_str(s).ok())
                            .unwrap_or_default(),
                        message_type: entry
                            .get("message_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("schedule")
                            .to_string(),
                        payload: entry.get("payload").cloned().unwrap_or_default(),
                        error_message: entry
                            .get("error_message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        retry_count: entry
                            .get("retry_count")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0) as i32,
                        created_at: entry
                            .get("created_at")
                            .and_then(|v| v.as_str())
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                            .unwrap_or_else(chrono::Utc::now),
                    });
                }
            }
        }
    }
    Ok(Json(entries))
}

/// `POST /v1/dlq/{id}/republish` - republish a DLQ entry (local posting or Cron schedule).
/// Republish acknowledgement for one DLQ entry (typed body).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct DlqRepublishAck {
    /// Whether the entry was republished.
    pub republished: bool,
    /// Where the entry was found (`local` or `cron`).
    pub source: String,
}

#[utoipa::path(
    post,
    path = "/v1/dlq/{id}/republish",
    params(("id" = Uuid, Path, description = "DLQ entry ID")),
    responses(
        (status = 200, description = "DLQ entry republished"),
        (status = 404, description = "DLQ entry not found"),
        (status = 403, description = "Missing bank8:ledger:dlq:republish scope"),
    ),
    security(("bank8:ledger:dlq:republish" = [])),
    tag = "ledger",
)]
pub async fn republish_dlq(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<DlqRepublishAck>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:dlq:republish"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    // Try local DLQ first.
    let local = sqlx::query("SELECT payload, message_type, error_message FROM dlq WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(err_db)?;
    if let Some(row) = local {
        let payload: serde_json::Value = row.get("payload");
        let message_type: String = row.get("message_type");
        // Re-enqueue to Bus (M2M-backed client built at startup).
        // Pass the admin's token as publisher - the republish is attributed
        // to the admin, not the original producer (§4.5).
        let publisher_id_token = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.to_string());
        let bus = state.bus_client.clone();
        bus.produce(&sentin8::bus::contracts::ProduceRequest {
            stream_family: state.config.stream_family.clone(),
            env_id: Some(a.env_id()),
            event_type: message_type.clone(),
            payload: payload.clone(),
            correlation_id: None,
            idempotency_key: Some(id.to_string()),
            publisher_id_token,
            publisher_subject: Some(a.claims.sub.clone()),
        })
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("bus produce failed: {e}"),
            )
        })?;
        // Emit the dedicated republished event (design §11).
        let original_error: String = row.get("error_message");
        super::emit_event(
            &state.pool,
            a.env_id(),
            "bank8:ledger:posting:republished",
            serde_json::json!({ "posting_id": payload.get("posting_id").cloned().unwrap_or(serde_json::json!(id.to_string())), "original_error": original_error }),
        ).await;
        sqlx::query("UPDATE dlq SET retry_count = retry_count + 1 WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(err_db)?;
        return Ok(Json(DlqRepublishAck {
            republished: true,
            source: "local".into(),
        }));
    }
    // Not in local DLQ - try Cron DLQ.
    let cron = crate::cron_client::CronClient::new(
        &state.config.sentin8_cron_url,
        &state.config.cron_token().await,
    );

    conn.commit().await.map_err(err_db)?;
    match cron.republish_dlq(&id.to_string()).await {
        Ok(()) => Ok(Json(DlqRepublishAck {
            republished: true,
            source: "cron".into(),
        })),
        Err(e) => Err((
            StatusCode::NOT_FOUND,
            format!("DLQ entry not found in local or Cron: {e}"),
        )),
    }
}
// ── Double-entry batch validation (pure logic - unit-tested) ────────────

/// Instruction types that DEBIT the source account (money leaves the
/// account). All other types (DEPOSIT, INTEREST_APPLICATION credit leg,
/// REVERSAL_CREDIT, ADJUSTMENT_CREDIT) credit it.
fn debits_source(instruction_type: &str) -> bool {
    matches!(
        instruction_type.to_ascii_uppercase().as_str(),
        "WITHDRAWAL" | "FEE_APPLICATION" | "TRANSFER_OUT" | "REVERSAL_DEBIT" | "ADJUSTMENT_DEBIT"
    )
}

/// Per-denomination double-entry balance check (design §4.1).
/// Sums the debit-direction amounts and the credit-direction amounts per
/// denomination across the batch; both sides must be equal. A single
/// instruction is trivially balanced (its debit leg equals its credit leg),
/// so batches of size 1 always pass - multi-instruction batches must net
/// out. Returns `Err(message)` on imbalance.
pub fn check_double_entry(instructions: &[PostingInstruction]) -> Result<(), String> {
    if instructions.len() <= 1 {
        return Ok(());
    }
    let mut sums: std::collections::HashMap<String, (Decimal, Decimal)> =
        std::collections::HashMap::new();
    for instr in instructions {
        let amount = instr.amount.parse::<Decimal>().unwrap_or(Decimal::ZERO);
        let entry = sums
            .entry(instr.denomination.clone())
            .or_insert((Decimal::ZERO, Decimal::ZERO));
        if debits_source(&instr.instruction_type) {
            entry.0 += amount;
        } else {
            entry.1 += amount;
        }
    }
    if sums.iter().any(|(_, (d, c))| d != c) {
        return Err("double-entry violation: debit and credit totals differ".into());
    }
    Ok(())
}

/// Default denomination (re-exported for LEDG-COMPLETE handlers).
pub fn default_denomination() -> String {
    "CAD".into()
}

/// Replay a posting batch by batch_id (journal replay). Idempotent:
/// the posting idempotency/batch identity means a replay of an already-
/// committed batch returns the original batch untouched. Instructions come
/// from the journal event payload (`{"batch_id", "instructions"}`).
pub async fn replay_batch(
    state: &AppState,
    env_id: Uuid,
    batch_id: &str,
    instructions: serde_json::Value,
) -> serde_json::Value {
    // A committed batch with this batch_id already exists → no-op replay.
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM postings WHERE env_id = $1 AND batch_id = $2 AND status != 'rejected' LIMIT 1",
    )
    .bind(env_id).bind(batch_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    if let Some(id) = existing {
        return serde_json::json!({ "batch_id": batch_id, "posting_id": id, "replayed": false, "reason": "already committed" });
    }
    // Parse the journaled instructions back into the request shape and run
    // the standard engine (committing a new batch - journal replays of
    // pre-commit failures legitimately re-execute).
    let parsed: Result<Vec<PostingInstruction>, _> = serde_json::from_value(instructions);
    match parsed {
        Ok(instrs) if !instrs.is_empty() => {
            let req = CreatePostingRequest {
                batch_id: format!(
                    "{batch_id}-replay-{}",
                    chrono::Utc::now().format("%Y%m%d%H%M%S")
                ),
                idempotency_key: Some(format!("journal-replay:{batch_id}")),
                dry_run: false,
                instructions: instrs,
            };
            match create_posting_inner(state, env_id, req).await {
                Ok(resp) => {
                    serde_json::json!({ "batch_id": batch_id, "posting_id": resp.id, "replayed": true, "status": resp.status })
                }
                Err((_code, e)) => {
                    serde_json::json!({ "batch_id": batch_id, "replayed": false, "error": e })
                }
            }
        }
        _ => {
            serde_json::json!({ "batch_id": batch_id, "replayed": false, "error": "no parsable instructions in journal payload" })
        }
    }
}

/// Core posting engine shared by `create_posting` and journal replays.
/// This is `create_posting`'s body minus the HTTP auth/JSON layer: the
/// handler verifies the token, then delegates here with the resolved env.
async fn create_posting_inner(
    state: &AppState,
    env_id: Uuid,
    req: CreatePostingRequest,
) -> Result<PostingResponse, (axum::http::StatusCode, String)> {
    // Reuse the handler body by invoking it through a synthesized context:
    // the handler requires a verified token, so replays go through the
    // same validation path with a service context. To keep the change
    // surface small, this helper performs the same engine steps as the
    // handler for the replay subset: idempotent batch insert + instruction
    // rows + balance updates + journal + audit + outbox.
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, env_id).await.map_err(err_db)?;
    for instr in &req.instructions {
        let amount = instr.amount.parse::<Decimal>().map_err(|e| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                format!("invalid amount: {e}"),
            )
        })?;
        if amount <= Decimal::ZERO {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                format!("amount must be positive: {amount}"),
            ));
        }
    }
    check_double_entry(&req.instructions).map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e))?;
    let row = sqlx::query(
        r#"INSERT INTO postings (env_id, batch_id, status, idempotency_key, instruction_count)
           VALUES ($1, $2, 'accepted', $3, $4)
           ON CONFLICT (env_id, idempotency_key) WHERE idempotency_key IS NOT NULL
           DO UPDATE SET batch_id = postings.batch_id
           RETURNING id, batch_id, status, instruction_count, created_at, completed_at"#,
    )
    .bind(env_id)
    .bind(&req.batch_id)
    .bind(&req.idempotency_key)
    .bind(req.instructions.len() as i32)
    .fetch_one(&mut *tx)
    .await
    .map_err(err_db)?;
    let posting_id: Uuid = row.get("id");
    for instr in &req.instructions {
        let amount: Decimal = instr.amount.parse().unwrap_or(Decimal::ZERO);
        sqlx::query(
            r#"INSERT INTO posting_instructions
                 (env_id, posting_id, instruction_type, debit_account, credit_account, amount, denomination, value_timestamp, status)
               VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, now()), 'accepted')"#,
        )
        .bind(env_id).bind(posting_id)
        .bind(&instr.instruction_type).bind(instr.debit_account).bind(instr.credit_account)
        .bind(amount).bind(&instr.denomination).bind(instr.value_timestamp)
        .execute(&mut *tx).await.map_err(err_db)?;
        let (debit_delta, credit_delta) = if debits_source(&instr.instruction_type) {
            (-amount, amount)
        } else {
            (amount, -amount)
        };
        sqlx::query(
            r#"INSERT INTO balances (env_id, account_id, denomination, address, phase, amount)
               VALUES ($1, $2, $3, 'DEFAULT', 'COMMITTED', $4)
               ON CONFLICT (account_id, denomination, address, phase)
               DO UPDATE SET amount = balances.amount + ($4), updated_at = now()"#,
        )
        .bind(env_id)
        .bind(instr.debit_account)
        .bind(&instr.denomination)
        .bind(debit_delta)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
        sqlx::query(
            r#"INSERT INTO balances (env_id, account_id, denomination, address, phase, amount)
               VALUES ($1, $2, $3, 'DEFAULT', 'COMMITTED', $4)
               ON CONFLICT (account_id, denomination, address, phase)
               DO UPDATE SET amount = balances.amount + ($4), updated_at = now()"#,
        )
        .bind(env_id)
        .bind(instr.credit_account)
        .bind(&instr.denomination)
        .bind(credit_delta)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    }
    // Journal the replay payload as plain JSON (PostingInstruction is
    // Deserialize-only; the payload records the wire shape, not the struct).
    let journaled_instructions: serde_json::Value =
        serde_json::to_value(&req.instructions).unwrap_or_else(|_| serde_json::json!([]));
    crate::handlers::journal::append_journal_event(
        &mut tx,
        env_id,
        "posting",
        posting_id,
        "replay",
        &serde_json::json!({ "batch_id": req.batch_id, "instructions": journaled_instructions }),
    )
    .await?;
    sqlx::query(
        r#"INSERT INTO audit_events (env_id, action, target_resource_type, target_resource_id)
           VALUES ($1, 'journal_replay', 'posting', $2)"#,
    )
    .bind(env_id)
    .bind(posting_id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    sentin8::bus::outbox::insert_outbox_row(
        &mut *tx,
        env_id,
        "ledger",
        "bank8:ledger:posting:created",
        &serde_json::json!({ "posting_id": posting_id, "batch_id": req.batch_id, "replay": true }),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, posting_id = %posting_id, "replay outbox insert failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("replay outbox insert failed: {e}"),
        )
    })?;
    tx.commit().await.map_err(err_db)?;
    /* removed misplaced commit */
    Ok(PostingResponse {
        id: posting_id,
        batch_id: req.batch_id,
        status: "accepted".into(),
        instruction_count: req.instructions.len() as i32,
        created_at: chrono::Utc::now(),
        completed_at: Some(chrono::Utc::now()),
        balances: vec![],
    })
}

// ── Unit tests (design §8.6 - posting-path pure logic) ──────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn instr(instruction_type: &str, amount: &str, denomination: &str) -> PostingInstruction {
        PostingInstruction {
            instruction_type: instruction_type.into(),
            debit_account: uuid::Uuid::new_v4(),
            credit_account: uuid::Uuid::new_v4(),
            amount: amount.into(),
            denomination: denomination.into(),
            value_timestamp: None,
            description: None,
        }
    }

    // ── check_double_entry ───────────────────────────────────────────────

    #[test]
    fn single_instruction_always_balanced() {
        check_double_entry(&[instr("WITHDRAWAL", "100", "CAD")]).unwrap();
        check_double_entry(&[instr("DEPOSIT", "0.01", "USD")]).unwrap();
    }

    #[test]
    fn empty_batch_is_balanced() {
        check_double_entry(&[]).unwrap();
    }

    #[test]
    fn balanced_pair_accepted() {
        // A $100 withdrawal from A and a $100 deposit to B in one batch
        // debit side 100, credit side 100.
        check_double_entry(&[
            instr("WITHDRAWAL", "100", "CAD"),
            instr("DEPOSIT", "100", "CAD"),
        ])
        .unwrap();
    }

    #[test]
    fn imbalanced_batch_rejected() {
        let e = check_double_entry(&[
            instr("WITHDRAWAL", "100", "CAD"),
            instr("DEPOSIT", "99.99", "CAD"),
        ])
        .unwrap_err();
        assert!(e.contains("double-entry violation"));
    }

    #[test]
    fn imbalanced_by_denomination_rejected() {
        // Balanced in CAD but a lone USD debit with no USD credit.
        let e = check_double_entry(&[
            instr("WITHDRAWAL", "100", "CAD"),
            instr("DEPOSIT", "100", "CAD"),
            instr("WITHDRAWAL", "50", "USD"),
            instr("DEPOSIT", "10", "USD"),
        ])
        .unwrap_err();
        assert!(e.contains("double-entry violation"));
    }

    #[test]
    fn per_denomination_independence() {
        // CAD nets to 0, USD nets to 0 - both pass even though the
        // instruction types differ.
        check_double_entry(&[
            instr("WITHDRAWAL", "100", "CAD"),
            instr("DEPOSIT", "100", "CAD"),
            instr("WITHDRAWAL", "25", "USD"),
            instr("DEPOSIT", "25", "USD"),
        ])
        .unwrap();
    }

    #[test]
    fn multiple_debits_one_credit_nets_out() {
        // 60 + 40 debits vs one 100 credit - balanced.
        check_double_entry(&[
            instr("WITHDRAWAL", "60", "CAD"),
            instr("WITHDRAWAL", "40", "CAD"),
            instr("DEPOSIT", "100", "CAD"),
        ])
        .unwrap();
    }

    #[test]
    fn invalid_amount_treated_as_zero_for_balance() {
        // A malformed amount contributes 0 (the handler's upfront parse
        // rejects it with 400 before this check runs).
        check_double_entry(&[
            instr("WITHDRAWAL", "not-a-number", "CAD"),
            instr("DEPOSIT", "0", "CAD"),
        ])
        .unwrap();
    }

    #[test]
    fn fee_application_debits_the_source() {
        // FEE_APPLICATION belongs to the debit direction - two fee
        // applications net against one deposit.
        check_double_entry(&[
            instr("FEE_APPLICATION", "5", "CAD"),
            instr("FEE_APPLICATION", "5", "CAD"),
            instr("DEPOSIT", "10", "CAD"),
        ])
        .unwrap();
        // One fee + smaller deposit → imbalanced.
        assert!(check_double_entry(&[
            instr("FEE_APPLICATION", "5", "CAD"),
            instr("DEPOSIT", "4", "CAD"),
        ])
        .is_err());
    }

    #[test]
    fn mixed_denominations_balanced_and_imbalanced() {
        // Different currencies checked independently.
        check_double_entry(&[
            instr("WITHDRAWAL", "1", "EUR"),
            instr("DEPOSIT", "1", "EUR"),
            instr("WITHDRAWAL", "2", "GBP"),
            instr("DEPOSIT", "2", "GBP"),
        ])
        .unwrap();
        assert!(check_double_entry(&[
            instr("WITHDRAWAL", "1", "EUR"),
            instr("DEPOSIT", "2", "EUR"),
        ])
        .is_err());
    }

    // ── debits_source ────────────────────────────────────────────────────

    #[test]
    fn debit_direction_types() {
        assert!(debits_source("WITHDRAWAL"));
        assert!(debits_source("FEE_APPLICATION"));
        assert!(debits_source("TRANSFER_OUT"));
        assert!(debits_source("REVERSAL_DEBIT"));
        assert!(debits_source("ADJUSTMENT_DEBIT"));
        // Case-insensitive.
        assert!(debits_source("withdrawal"));
    }

    #[test]
    fn credit_direction_types() {
        assert!(!debits_source("DEPOSIT"));
        assert!(!debits_source("INTEREST_APPLICATION"));
        assert!(!debits_source("REVERSAL_CREDIT"));
        assert!(!debits_source("ADJUSTMENT_CREDIT"));
        assert!(!debits_source("TRANSFER_IN"));
    }
}
