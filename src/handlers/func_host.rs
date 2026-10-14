// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Func proxy-back endpoint — host functions for WASM modules.
//! Sentin8:Func executes a hook's WASM module and, when the module calls a
//! host function, proxy-calls the ledger's internal API at
//! `/v1/internal/func-host` (the path every `call_hook` request advertises in
//! its `CallbackConfig.internal_path`). The ledger owns the host-function
//! map — Sentin8:Func resolves it dynamically, no pre-registration.
//! Host functions:
//! - `get_account` — account row by id
//! - `get_balance` — committed balance by account + denomination
//! - `set_flag` — upsert `ACCOUNT_*` flag on an account
//! - `create_posting` — submit a single posting instruction batch

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use rust_decimal::Decimal;
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{err_db, set_tenant_context, AppState};

#[derive(Debug, Deserialize)]
pub struct FuncHostRequest {
    /// Host function name (from the CallbackConfig host_functions map).
    pub function: String,
    /// Positional/keyword arguments for the host function.
    #[serde(default)]
    pub args: serde_json::Value,
    /// The env the hook runs in — stamped by the Func runtime from the
    /// hook context (`env_id`), never client-selectable.
    pub env_id: Uuid,
}

#[derive(Debug, serde::Serialize)]
pub struct FuncHostResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `POST /v1/internal/func-host` — Sentin8:Func proxy-back for host functions.
/// Authorization: M2M token with `bank8:ledger:postings:write` (the Func
/// runtime authenticates with the posting service's M2M identity because
/// host functions can move money). Tenant context comes from the `env_id`
/// in the request body — the Func runtime resolves it from the hook
/// context, and the M2M token's own env claim is cross-checked.
pub async fn func_host(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<FuncHostRequest>,
) -> Result<Json<FuncHostResponse>, (StatusCode, String)> {
    // Step 5 — Shield decides (principles §5.2, policy design §4.3). The
    // Func proxy-back path (M2M) evaluates the same enforced scope-mirror
    // set: its live scope set carries `bank8:ledger:postings:write`, so the
    // mirror permit for this action allows it. token type never bypasses
    // policy (`token_tp` is context, not an exemption — principles §5.2a).
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:write"),
    )
    .await?;
    // Cross-check: the Func runtime must call for an env its token can
    // address (platform M2M tokens carry `sys` env; ledger-scoped M2M carry
    // their own). Requests for a different env are rejected unless the
    // caller is the platform.
    if a.env_id() != req.env_id && !a.is_platform_admin() {
        return Err((StatusCode::FORBIDDEN, "func-host env mismatch".into()));
    }

    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, req.env_id)
        .await
        .map_err(err_db)?;

    match req.function.as_str() {
        "get_account" => {
            let id = req
                .args
                .get("account_id")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
                .or_else(|| {
                    req.args
                        .get("0")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok())
                })
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "get_account: account_id required".into(),
                ))?;
            let row = sqlx::query(
                r#"SELECT id, account_type, product_type, nickname, denomination, status
                     FROM accounts WHERE id = $1 AND env_id = $2 AND deleted_at IS NULL"#,
            )
            .bind(id)
            .bind(req.env_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(err_db)?
            .ok_or((StatusCode::NOT_FOUND, format!("account {id} not found")))?;
            Ok(Json(FuncHostResponse {
                ok: true,
                result: Some(serde_json::json!({
                    "account_id": row.get::<Uuid, _>("id"),
                    "account_type": row.get::<String, _>("account_type"),
                    "product_type": row.get::<Option<String>, _>("product_type"),
                    "nickname": row.get::<Option<String>, _>("nickname"),
                    "denomination": row.get::<String, _>("denomination"),
                    "status": row.get::<String, _>("status"),
                })),
                error: None,
            }))
        }
        "get_balance" => {
            let id = req
                .args
                .get("account_id")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
                .or_else(|| {
                    req.args
                        .get("0")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok())
                })
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "get_balance: account_id required".into(),
                ))?;
            let denom = req
                .args
                .get("denomination")
                .and_then(|v| v.as_str())
                .unwrap_or("CAD");
            let amount: Option<Decimal> = sqlx::query_scalar(
                r#"SELECT amount FROM balances
                    WHERE account_id = $1 AND denomination = $2 AND address = 'DEFAULT' AND phase = 'COMMITTED'"#,
            )
            .bind(id).bind(denom)
            .fetch_optional(&mut *conn).await.map_err(err_db)?;
            Ok(Json(FuncHostResponse {
                ok: true,
                result: Some(serde_json::json!({
                    "account_id": id,
                    "denomination": denom,
                    "balance": amount.unwrap_or(Decimal::ZERO).to_string(),
                })),
                error: None,
            }))
        }
        "set_flag" => {
            let id = req
                .args
                .get("account_id")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "set_flag: account_id required".into(),
                ))?;
            let flag_name = req.args.get("flag_name").and_then(|v| v.as_str()).ok_or((
                StatusCode::BAD_REQUEST,
                "set_flag: flag_name required".into(),
            ))?;
            let value = req
                .args
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("ON");
            sqlx::query(
                r#"INSERT INTO account_flags (env_id, account_id, flag_name, value)
                   VALUES ($1, $2, $3, $4)
                   ON CONFLICT (account_id, flag_name)
                   DO UPDATE SET value = $4, updated_at = now()"#,
            )
            .bind(req.env_id)
            .bind(id)
            .bind(flag_name)
            .bind(value)
            .execute(&mut *conn)
            .await
            .map_err(err_db)?;
            Ok(Json(FuncHostResponse {
                ok: true,
                result: Some(serde_json::json!({ "flag": flag_name, "value": value })),
                error: None,
            }))
        }
        "create_posting" => {
            let instruction_type = req
                .args
                .get("instruction_type")
                .and_then(|v| v.as_str())
                .unwrap_or("ADJUSTMENT");
            let debit = req
                .args
                .get("debit_account")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "create_posting: debit_account required".into(),
                ))?;
            let credit = req
                .args
                .get("credit_account")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "create_posting: credit_account required".into(),
                ))?;
            let amount_s = req
                .args
                .get("amount")
                .and_then(|v| {
                    v.as_str()
                        .map(String::from)
                        .or_else(|| v.as_f64().map(|f| f.to_string()))
                })
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "create_posting: amount required".into(),
                ))?;
            let amount = amount_s.parse::<Decimal>().map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("create_posting: invalid amount: {e}"),
                )
            })?;
            let denom = req
                .args
                .get("denomination")
                .and_then(|v| v.as_str())
                .unwrap_or("CAD");
            let batch_id = req
                .args
                .get("batch_id")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| format!("func-host-{}", Uuid::new_v4()));
            let mut tx = state.pool.begin().await.map_err(err_db)?;
            set_tenant_context(&mut tx, req.env_id)
                .await
                .map_err(err_db)?;
            let prow = sqlx::query(
                r#"INSERT INTO postings (env_id, batch_id, status, idempotency_key, instruction_count)
                   VALUES ($1, $2, 'accepted', $3, 1)
                   RETURNING id"#,
            )
            .bind(req.env_id).bind(&batch_id).bind(req.args.get("idempotency_key").and_then(|v| v.as_str()))
            .fetch_one(&mut *tx).await.map_err(err_db)?;
            let posting_id: Uuid = prow.get("id");
            sqlx::query(
                r#"INSERT INTO posting_instructions
                     (env_id, posting_id, instruction_type, debit_account, credit_account, amount, denomination, value_timestamp, status)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, now(), 'accepted')"#,
            )
            .bind(req.env_id).bind(posting_id).bind(instruction_type).bind(debit).bind(credit)
            .bind(amount).bind(denom)
            .execute(&mut *tx).await.map_err(err_db)?;
            sqlx::query(
                r#"INSERT INTO balances (env_id, account_id, denomination, address, phase, amount)
                   VALUES ($1, $2, $3, 'DEFAULT', 'COMMITTED', -($4))
                   ON CONFLICT (account_id, denomination, address, phase)
                   DO UPDATE SET amount = balances.amount - ($4), updated_at = now()"#,
            )
            .bind(req.env_id)
            .bind(debit)
            .bind(denom)
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
            .bind(req.env_id)
            .bind(credit)
            .bind(denom)
            .bind(amount)
            .execute(&mut *tx)
            .await
            .map_err(err_db)?;
            sqlx::query(
                r#"INSERT INTO audit_events (env_id, action, target_resource_type, target_resource_id)
                   VALUES ($1, $2, 'posting', $3)"#,
            )
            .bind(req.env_id).bind("func_host_create_posting").bind(posting_id.to_string())
            .execute(&mut *tx).await.map_err(err_db)?;
            tx.commit().await.map_err(err_db)?;
            Ok(Json(FuncHostResponse {
                ok: true,
                result: Some(serde_json::json!({ "posting_id": posting_id })),
                error: None,
            }))
        }
        other => Ok(Json(FuncHostResponse {
            ok: false,
            result: None,
            error: Some(format!("unknown host function: {other}")),
        })),
    }
}
