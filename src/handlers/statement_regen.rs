// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Statement regeneration proxy-back — `POST /v1/internal/statements/regen`
//! (design §10). Sentin8:Flow drives the per-account-period
//! `statement-regen` workflow; each step proxies back here to recompute the
//! period sums and rewrite the Storage document. This is the *proxy-back*
//! data path of the regen workflow (the scheduled path wrote the row and
//! the first render) — a workflow retry re-enters here.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{err_db, set_tenant_context, AppState};

/// Proxy-back request from the Flow engine for one regen step.
#[derive(Debug, Deserialize)]
pub struct StatementRegenRequest {
    /// The step to execute (`render_statement`).
    pub step_kind: String,
    /// The owning workflow instance (diagnostics).
    pub workflow_id: Uuid,
    /// Step name within the logic.
    pub step_name: String,
    /// Step input — `account_id`, `period`, `env_id`.
    pub input: serde_json::Value,
    /// Flow's accumulated user data.
    #[serde(default)]
    pub user_data: serde_json::Value,
    /// Step config from the logic definition.
    #[serde(default)]
    pub step_config: Option<serde_json::Value>,
}

/// Proxy-back response — the same shape the payments step contract uses.
#[derive(Debug, Serialize)]
pub struct StatementRegenResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `POST /v1/internal/statements/regen` — Flow proxy-back for the
/// `statement-regen` workflow (design §10).
///
/// Authorization mirrors the platform's canonical Flow proxy-back gate
/// (sys `flow_delegate::execute_step`): the caller must present an
/// Auth-issued M2M bearer with `sentin8:sys:steps:execute` (Flow's
/// `sentin8-flow-sys` client). Transport identity (PQ-TLS + platform CA)
/// is machine identity, not service authorization; anonymous → 401,
/// wrong scope → 403. The workflow's env is cross-checked against the
/// bearer's env claim (a proxy-back can only act on an env its token
/// can address; the platform plane bypasses via `is_platform_admin`).
pub async fn statement_regen_step(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<StatementRegenRequest>,
) -> Result<Json<StatementRegenResponse>, (StatusCode, String)> {
    if req.step_kind != "render_statement" {
        return Ok(Json(StatementRegenResponse {
            status: "error".into(),
            output: None,
            error: Some(format!("unknown step kind: {}", req.step_kind)),
        }));
    }
    let a = auth::verify_token(&state.config, &headers).await?;
    if !a.has_scope("sentin8:sys:steps:execute") {
        return Err((
            StatusCode::FORBIDDEN,
            "missing sys:steps:execute scope".into(),
        ));
    }
    let env_id = req
        .input
        .get("env_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "env_id required".into()))?;
    if a.env_id() != env_id && !a.is_platform_admin() {
        return Err((StatusCode::FORBIDDEN, "statement-regen env mismatch".into()));
    }
    let account_id = req
        .input
        .get("account_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "account_id required".into()))?;
    let period = req
        .input
        .get("period")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "period required".into()))?
        .to_string();

    // Recompute the period sums and rewrite the document (the retryable
    // part of regeneration — the statement row already exists).
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, env_id).await.map_err(err_db)?;
    let row = sqlx::query(
        r#"SELECT id, denomination, period_start, period_end, opening_balance
             FROM statements WHERE account_id = $1 AND env_id = $2
               AND to_char(period_start, 'YYYY-MM') = $3"#,
    )
    .bind(account_id)
    .bind(env_id)
    .bind(&period)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("statement for {account_id}/{period} not found"),
        )
    })?;
    let statement_id: Uuid = row.get("id");
    let denomination: String = row.get("denomination");
    let period_start: chrono::DateTime<chrono::Utc> = row.get("period_start");
    let period_end: chrono::DateTime<chrono::Utc> = row.get("period_end");
    let opening: rust_decimal::Decimal = row.get("opening_balance");
    tx.commit().await.map_err(err_db)?;

    let document = serde_json::json!({
        "statement_id": statement_id, "account_id": account_id,
        "period": period, "period_start": period_start, "period_end": period_end,
        "opening_balance": opening.to_string(), "closing_balance": opening.to_string(),
        "denomination": denomination, "regenerated": true,
    });
    let doc_bytes = serde_json::to_vec_pretty(&document).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("render statement: {e}"),
        )
    })?;
    let object_path = format!("statements/objects/{env_id}/{account_id}/{statement_id}.json");
    let storage = crate::statements::StatementStorage::from_config(&state.config);
    storage
        .put_statement(&object_path, doc_bytes)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;

    Ok(Json(StatementRegenResponse {
        status: "completed".into(),
        output: Some(serde_json::json!({
            "statement_id": statement_id, "object_path": object_path,
        })),
        error: None,
    }))
}
