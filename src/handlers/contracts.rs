// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Contract modules / events / simulate / supervisor contracts.
//! Contract logic runs in Sentin8:Func WASM modules; this module exposes:
//! - the Func-module catalog view derived from products' `contract_modules`,
//! - the contract execution history (audit view),
//! - `POST /v1/contracts/simulate` — execute a module hook against synthetic
//! account state with **no persistence** (preview/dry-run),
//! - supervisor contracts (cross-account contracts with member accounts).

use axum::{
    extract::{Path, State},
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

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct SupervisorContractResponse {
    pub id: Uuid,
    pub name: String,
    pub func_module_id: String,
    pub member_account_ids: JsonValue,
    pub parameters: JsonValue,
    pub status: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSupervisorContractRequest {
    pub name: String,
    pub func_module_id: String,
    #[serde(default)]
    pub member_account_ids: JsonValue,
    #[serde(default)]
    pub parameters: JsonValue,
}

/// `POST /v1/supervisor-contracts` — create a cross-account contract.
#[utoipa::path(
    post,
    path = "/v1/supervisor-contracts",
    request_body = CreateSupervisorContractRequest,
    responses(
        (status = 200, description = "Supervisor contract created", body = SupervisorContractResponse),
        (status = 409, description = "Name exists"),
        (status = 403, description = "Missing bank8:ledger:products:write scope"),
    ),
    security(("bank8:ledger:products:write" = [])),
    tag = "ledger",
)]
pub async fn create_supervisor_contract(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateSupervisorContractRequest>,
) -> Result<Json<SupervisorContractResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:products:write"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"INSERT INTO supervisor_contracts (env_id, name, func_module_id, member_account_ids, parameters)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, name, func_module_id, member_account_ids, parameters, status"#,
    )
    .bind(a.env_id()).bind(&req.name).bind(&req.func_module_id)
    .bind(&req.member_account_ids).bind(&req.parameters)
    .fetch_one(&mut *conn)
    .await;
    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            return Err((
                StatusCode::CONFLICT,
                "supervisor contract already exists".into(),
            ));
        }
        Err(e) => return Err(err_db(e)),
    };
    let contract_id: Uuid = row.get("id");
    emit_event(&state.pool, a.env_id(), "bank8:ledger:supervisorcontract:created",
        serde_json::json!({ "contract_id": contract_id, "member_account_ids": req.member_account_ids }))
        .await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(SupervisorContractResponse {
        id: contract_id,
        name: row.get("name"),
        func_module_id: row.get("func_module_id"),
        member_account_ids: row.get("member_account_ids"),
        parameters: row.get("parameters"),
        status: row.get("status"),
    }))
}

/// `GET /v1/supervisor-contracts` — list supervisor contracts.
#[utoipa::path(
    get,
    path = "/v1/supervisor-contracts",
    responses(
        (status = 200, description = "Supervisor contracts", body = [SupervisorContractResponse]),
        (status = 403, description = "Missing bank8:ledger:products:read scope"),
    ),
    security(("bank8:ledger:products:read" = [])),
    tag = "ledger",
)]
pub async fn list_supervisor_contracts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SupervisorContractResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:products:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT id, name, func_module_id, member_account_ids, parameters, status
             FROM supervisor_contracts WHERE env_id = $1 ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| SupervisorContractResponse {
                id: r.get("id"),
                name: r.get("name"),
                func_module_id: r.get("func_module_id"),
                member_account_ids: r.get("member_account_ids"),
                parameters: r.get("parameters"),
                status: r.get("status"),
            })
            .collect(),
    ))
}

/// `GET /v1/supervisor-contracts/{id}` — supervisor contract detail.
#[utoipa::path(
    get,
    path = "/v1/supervisor-contracts/{id}",
    responses(
        (status = 200, description = "Supervisor contract", body = SupervisorContractResponse),
        (status = 404, description = "Not found"),
    ),
    security(("bank8:ledger:products:read" = [])),
    tag = "ledger",
)]
pub async fn get_supervisor_contract(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<SupervisorContractResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:products:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"SELECT id, name, func_module_id, member_account_ids, parameters, status
             FROM supervisor_contracts WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((
        StatusCode::NOT_FOUND,
        format!("supervisor contract {id} not found"),
    ))?;
    Ok(Json(SupervisorContractResponse {
        id: row.get("id"),
        name: row.get("name"),
        func_module_id: row.get("func_module_id"),
        member_account_ids: row.get("member_account_ids"),
        parameters: row.get("parameters"),
        status: row.get("status"),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SimulateContractRequest {
    /// Func module id (the hook logic to execute).
    pub module_id: String,
    /// Hook name (pre_posting, post_posting, scheduled_event, activation, deactivation).
    #[serde(default = "default_hook")]
    pub hook: String,
    /// Synthetic account state — no persistence occurs.
    #[serde(default)]
    pub account: JsonValue,
    #[serde(default)]
    pub parameters: JsonValue,
    #[serde(default)]
    pub input: JsonValue,
}
fn default_hook() -> String {
    "pre_posting".into()
}

/// `POST /v1/contracts:simulate` — execute a module hook against synthetic
/// account state . Calls Sentin8:Func `POST /v1/modules/{id}/execute`
/// with a mock host-function context; **no persistence occurs** — the raw
/// hook result is returned for preview/dry-run use.
#[utoipa::path(
    post,
    path = "/v1/contracts/simulate",
    request_body = SimulateContractRequest,
    responses(
        (status = 200, description = "Simulation result (raw Func hook output)"),
        (status = 503, description = "Sentin8:Func not configured"),
        (status = 403, description = "Missing bank8:ledger:postings:write scope"),
    ),
    security(("bank8:ledger:postings:write" = [])),
    tag = "ledger",
)]
pub async fn simulate_contract(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SimulateContractRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:write"),
    )
    .await?;
    if state.config.sentin8_func_url.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Sentin8:Func not configured".into(),
        ));
    }
    // Certificate-presenting client (CERTFREE-4F) — the `ledger`
    // workload certificate presents in the TLS handshake; the callback
    // token is the separate proxy-back contract.
    let client = match state.config.func_client.clone() {
        Some(c) => c,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "Func transport absent (workload certificate not provisioned)".into(),
            ))
        }
    };
    let callback_base = crate::func_hooks::callback_base_url(&state.config);
    let callback_token = state.config.func_token().await;
    let ctx = serde_json::json!({
        "simulate": true,
        "hook": req.hook,
        "account": req.account,
        "parameters": req.parameters,
        "input": req.input,
        "env_id": a.env_id(),
    });
    let result = crate::func_hooks::call_hook_raw(
        &client,
        &req.module_id,
        &req.hook,
        ctx,
        Some(&callback_base),
        Some(&callback_token),
        Some("/v1/internal/func-host"),
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, format!("simulation failed: {e}")))?;
    // Simulation is journaled (append-only; no domain rows written).
    let sim_ref = Uuid::new_v4();
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, a.env_id())
        .await
        .map_err(err_db)?;
    append_journal_event(
        &mut tx,
        a.env_id(),
        "contract",
        sim_ref,
        "simulate",
        &serde_json::json!({ "module_id": req.module_id, "hook": req.hook }),
    )
    .await?;
    tx.commit().await.map_err(err_db)?;
    Ok(Json(result))
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct ContractModuleResponse {
    pub module_id: String,
    pub product_id: Option<Uuid>,
    pub hooks: Vec<String>,
}

/// `GET /v1/contract-modules` — contract module catalog (Func modules
/// registered per product; sourced from the products' contract_modules field).
#[utoipa::path(
    get,
    path = "/v1/contract-modules",
    responses(
        (status = 200, description = "Contract module catalog", body = [ContractModuleResponse]),
        (status = 403, description = "Missing bank8:ledger:products:read scope"),
    ),
    security(("bank8:ledger:products:read" = [])),
    tag = "ledger",
)]
pub async fn list_contract_modules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ContractModuleResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:products:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT id, contract_modules FROM products
            WHERE env_id = $1 AND contract_modules IS NOT NULL"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let mut modules: Vec<ContractModuleResponse> = Vec::new();
    for r in &rows {
        let product_id: Uuid = r.get("id");
        let cms: JsonValue = r
            .get::<Option<JsonValue>, _>("contract_modules")
            .unwrap_or_else(|| serde_json::json!([]));
        // contract_modules may be a list of names or a list of objects with
        // a module/hook shape; both are surfaced.
        if let Some(list) = cms.as_array() {
            for entry in list {
                let (module_id, hooks) = if entry.is_string() {
                    (
                        entry.as_str().unwrap_or_default().to_string(),
                        vec![
                            "pre_posting".into(),
                            "post_posting".into(),
                            "scheduled_event".into(),
                        ],
                    )
                } else {
                    (
                        entry
                            .get("module_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string(),
                        entry
                            .get("hooks")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|h| h.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    )
                };
                if module_id.is_empty() {
                    continue;
                }
                modules.push(ContractModuleResponse {
                    module_id,
                    product_id: Some(product_id),
                    hooks,
                });
            }
        }
    }
    Ok(Json(modules))
}

/// `GET /v1/contract-events` — contract execution history (audit events with
/// target_resource_type='contract'/'func_hook').
#[utoipa::path(
    get,
    path = "/v1/contract-events",
    responses(
        (status = 200, description = "Contract execution events", body = [crate::handlers::audit::AuditEventResponse]),
        (status = 403, description = "Missing bank8:ledger:audit:read scope"),
    ),
    security(("bank8:ledger:audit:read" = [])),
    tag = "ledger",
)]
pub async fn list_contract_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::handlers::audit::AuditEventResponse>>, (StatusCode, String)> {
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
            WHERE env_id = $1 AND target_resource_type IN ('contract', 'func_hook', 'supervisor_contract')
            ORDER BY timestamp DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| crate::handlers::audit::AuditEventResponse {
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
