// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Internal accounts — counterparty plumbing (cash deposit, clearing,
//! suspense, liquidity, …) over `accounts` with `account_type='internal'`.
//! Reads honour the §10.1 staff-realm `?env_id=` override (org-validated) via
//! the shared `set_tenant_context_ext` resolution.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use rust_decimal::Decimal;
use serde::Deserialize;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{emit_event, err_db, set_tenant_context_ext, AppState};

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct InternalAccountResponse {
    pub id: Uuid,
    pub nickname: Option<String>,
    pub product_type: Option<String>,
    pub denomination: String,
    pub status: String,
    pub current_balance: Option<Decimal>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateInternalAccountRequest {
    pub nickname: String,
    pub product_type: String,
    #[serde(default = "crate::handlers::postings::default_denomination")]
    pub denomination: String,
}

/// `POST /v1/internal-accounts` — create an internal account
/// (counterparty plumbing: cash deposit, clearing, suspense, etc.).
#[utoipa::path(
    post,
    path = "/v1/internal-accounts",
    request_body = CreateInternalAccountRequest,
    responses(
        (status = 200, description = "Internal account created", body = InternalAccountResponse),
        (status = 409, description = "Nickname exists"),
        (status = 403, description = "Missing bank8:ledger:accounts:write scope"),
    ),
    security(("bank8:ledger:accounts:write" = [])),
    tag = "ledger",
)]
pub async fn create_internal_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateInternalAccountRequest>,
) -> Result<Json<InternalAccountResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:write"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, a.env_id(), &a)
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"INSERT INTO accounts (env_id, account_type, product_type, nickname, denomination, status)
           VALUES ($1, 'internal', $2, $3, $4, 'active')
           RETURNING id, nickname, product_type, denomination, status"#,
    )
    .bind(a.env_id()).bind(&req.product_type).bind(&req.nickname).bind(&req.denomination)
    .fetch_one(&mut *conn)
    .await;
    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            return Err((
                StatusCode::CONFLICT,
                "internal account nickname already exists".into(),
            ));
        }
        Err(e) => return Err(err_db(e)),
    };
    let account_id: Uuid = row.get("id");
    emit_event(&state.pool, a.env_id(), "bank8:ledger:internalaccount:created",
        serde_json::json!({ "account_id": account_id, "nickname": req.nickname, "product_type": req.product_type }))
        .await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(InternalAccountResponse {
        id: account_id,
        nickname: row.get("nickname"),
        product_type: row.get("product_type"),
        denomination: row.get("denomination"),
        status: row.get("status"),
        current_balance: None,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListInternalAccountsQuery {
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default)]
    pub product_type: Option<String>,
}

/// `GET /v1/internal-accounts` — list internal accounts (nickname/product_type
/// filter). Staff-realm callers may pass the org-validated `?env_id=` override
/// per tenant-isolation design §10.1 (handled by the shared env resolution).
#[utoipa::path(
    get,
    path = "/v1/internal-accounts",
    responses(
        (status = 200, description = "Internal accounts", body = [InternalAccountResponse]),
        (status = 403, description = "Missing bank8:ledger:accounts:read scope"),
    ),
    security(("bank8:ledger:accounts:read" = [])),
    tag = "ledger",
)]
pub async fn list_internal_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListInternalAccountsQuery>,
) -> Result<Json<Vec<InternalAccountResponse>>, (StatusCode, String)> {
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
    let rows = sqlx::query(
        r#"SELECT a.id, a.nickname, a.product_type, a.denomination, a.status,
                  b.amount AS current_balance
             FROM accounts a
             LEFT JOIN balances b ON b.account_id = a.id AND b.phase = 'COMMITTED'
            WHERE a.env_id = $1 AND a.account_type = 'internal' AND a.deleted_at IS NULL
              AND ($2::text IS NULL OR a.nickname = $2)
              AND ($3::text IS NULL OR a.product_type = $3)
            ORDER BY a.nickname"#,
    )
    .bind(a.env_id())
    .bind(q.nickname.as_deref())
    .bind(q.product_type.as_deref())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| InternalAccountResponse {
                id: r.get("id"),
                nickname: r.get("nickname"),
                product_type: r.get("product_type"),
                denomination: r.get("denomination"),
                status: r.get("status"),
                current_balance: r.get("current_balance"),
            })
            .collect(),
    ))
}

/// `GET /v1/internal-accounts/{id}` — internal account detail.
#[utoipa::path(
    get,
    path = "/v1/internal-accounts/{id}",
    responses(
        (status = 200, description = "Internal account", body = InternalAccountResponse),
        (status = 404, description = "Not found"),
    ),
    security(("bank8:ledger:accounts:read" = [])),
    tag = "ledger",
)]
pub async fn get_internal_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<InternalAccountResponse>, (StatusCode, String)> {
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
        r#"SELECT a.id, a.nickname, a.product_type, a.denomination, a.status,
                  b.amount AS current_balance
             FROM accounts a
             LEFT JOIN balances b ON b.account_id = a.id AND b.phase = 'COMMITTED'
            WHERE a.id = $1 AND a.env_id = $2 AND a.account_type = 'internal' AND a.deleted_at IS NULL"#,
    )
    .bind(id).bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, format!("internal account {id} not found")))?;
    Ok(Json(InternalAccountResponse {
        id: row.get("id"),
        nickname: row.get("nickname"),
        product_type: row.get("product_type"),
        denomination: row.get("denomination"),
        status: row.get("status"),
        current_balance: row.get("current_balance"),
    }))
}
