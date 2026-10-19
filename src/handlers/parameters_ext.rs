// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Derived + global parameters.
//! - `GET /v1/derived-parameter-values` computes the derived values for an
//! account via the shared module engine (`modules::compute_derived_parameters`).
//! - Global parameters (`global_parameters`) are env-wide named
//! values with a declared shape; resolution order is global → product →
//! account (design §5.3d).

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{err_db, set_tenant_context, set_tenant_context_ext, AppState};

// ── Derived parameters  ───────────────────────────────────────────

/// `GET /v1/derived-parameter-values?account_id=` - computed derived values.
#[utoipa::path(
    get,
    path = "/v1/derived-parameter-values",
    params(("account_id" = Uuid, Query, description = "Account id")),
    responses(
        (status = 200, description = "Derived parameter values", body = JsonValue),
        (status = 400, description = "account_id required"),
        (status = 403, description = "Missing bank8:ledger:accounts:read scope"),
    ),
    security(("bank8:ledger:accounts:read" = [])),
    tag = "ledger",
)]
pub async fn get_derived_parameters(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DerivedParamsQuery>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let account_id = q.account_id.ok_or((
        StatusCode::BAD_REQUEST,
        "account_id query parameter required".into(),
    ))?;
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, a.env_id(), &a)
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"SELECT a.id, a.product_type, a.denomination, a.opened_at, a.status,
                  p.parameters AS product_parameters, p.modules AS product_modules,
                  COALESCE(b.amount, 0) AS current_balance
             FROM accounts a
             LEFT JOIN products p ON p.id = a.product_id
             LEFT JOIN balances b ON b.account_id = a.id AND b.phase = 'COMMITTED'
            WHERE a.id = $1 AND a.env_id = $2 AND a.deleted_at IS NULL"#,
    )
    .bind(account_id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((
        StatusCode::NOT_FOUND,
        format!("account {account_id} not found"),
    ))?;

    let now = chrono::Utc::now();
    let account = crate::types::AccountV2 {
        id: account_id,
        env_id: a.env_id(),
        customer_id: None,
        product_id: None,
        account_type: "CUSTOMER".into(),
        product_type: row.get("product_type"),
        nickname: None,
        status: row.get("status"),
        denomination: row.get("denomination"),
        permitted_denominations: vec![],
        tside: "LIABILITY".into(),
        processing_group_id: None,
        sentin8_func_version_id: None,
        pending_sentin8_func_version_id: None,
        stakeholder_ids: vec![],
        opened_at: row.get("opened_at"),
        closed_at: None,
        created_at: now,
        updated_at: now,
    };
    let modules: Vec<String> = row
        .get::<Option<JsonValue>, _>("product_modules")
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    let params = row
        .get::<Option<JsonValue>, _>("product_parameters")
        .unwrap_or_else(|| serde_json::json!({}));
    let balance: Decimal = row.get("current_balance");
    let ctx = crate::modules::ModuleContext {
        product_parameters: &params,
        modules: &modules,
        instance_params: &serde_json::json!({}),
    };
    Ok(Json(crate::modules::compute_derived_parameters(
        &ctx, &account, balance,
    )))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DerivedParamsQuery {
    #[serde(default)]
    pub account_id: Option<Uuid>,
}

// ── Global parameters  ────────────────────────────────────────────

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct GlobalParameterResponse {
    pub id: Uuid,
    pub name: String,
    pub shape: JsonValue,
    pub value: JsonValue,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertGlobalParameterRequest {
    pub name: String,
    #[serde(default)]
    pub shape: JsonValue,
    #[serde(default)]
    pub value: JsonValue,
}

/// `POST /v1/global-parameters` - create/update a global parameter.
#[utoipa::path(
    post,
    path = "/v1/global-parameters",
    request_body = UpsertGlobalParameterRequest,
    responses(
        (status = 200, description = "Global parameter upserted", body = GlobalParameterResponse),
        (status = 403, description = "Missing bank8:ledger:products:write scope"),
    ),
    security(("bank8:ledger:products:write" = [])),
    tag = "ledger",
)]
pub async fn upsert_global_parameter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpsertGlobalParameterRequest>,
) -> Result<Json<GlobalParameterResponse>, (StatusCode, String)> {
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
        r#"INSERT INTO global_parameters (env_id, name, shape, value)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (env_id, name) DO UPDATE
             SET shape = EXCLUDED.shape, value = EXCLUDED.value, updated_at = now()
           RETURNING id, name, shape, value, updated_at"#,
    )
    .bind(a.env_id())
    .bind(&req.name)
    .bind(req.shape)
    .bind(req.value)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(GlobalParameterResponse {
        id: row.get("id"),
        name: row.get("name"),
        shape: row.get("shape"),
        value: row.get("value"),
        updated_at: row.get("updated_at"),
    }))
}

/// `GET /v1/global-parameters` - list global parameters.
#[utoipa::path(
    get,
    path = "/v1/global-parameters",
    responses(
        (status = 200, description = "Global parameters", body = [GlobalParameterResponse]),
        (status = 403, description = "Missing bank8:ledger:products:read scope"),
    ),
    security(("bank8:ledger:products:read" = [])),
    tag = "ledger",
)]
pub async fn list_global_parameters(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<GlobalParameterResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, name, shape, value, updated_at FROM global_parameters
            WHERE env_id = $1 ORDER BY name"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| GlobalParameterResponse {
                id: r.get("id"),
                name: r.get("name"),
                shape: r.get("shape"),
                value: r.get("value"),
                updated_at: r.get("updated_at"),
            })
            .collect(),
    ))
}

/// `GET /v1/global-parameters/{id}` - global parameter detail.
#[utoipa::path(
    get,
    path = "/v1/global-parameters/{id}",
    responses(
        (status = 200, description = "Global parameter", body = GlobalParameterResponse),
        (status = 404, description = "Not found"),
    ),
    security(("bank8:ledger:products:read" = [])),
    tag = "ledger",
)]
pub async fn get_global_parameter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<GlobalParameterResponse>, (StatusCode, String)> {
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
        r#"SELECT id, name, shape, value, updated_at FROM global_parameters WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((
        StatusCode::NOT_FOUND,
        format!("global parameter {id} not found"),
    ))?;
    Ok(Json(GlobalParameterResponse {
        id: row.get("id"),
        name: row.get("name"),
        shape: row.get("shape"),
        value: row.get("value"),
        updated_at: row.get("updated_at"),
    }))
}
