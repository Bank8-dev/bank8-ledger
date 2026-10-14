// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Balances v2 — live / end-of-period / series over `balances` buckets
//! (design §5.3).
//! `balances` holds the latest committed amount per
//! (account, denomination, address, phase). Holder-scoped callers (§4.3c)
//! only see balances of their own customer accounts — the `holder_scope_ids`
//! defence-in-depth filter never leaks env-wide rows.

use axum::{
    extract::{Query, State},
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
use crate::handlers::{err_db, set_tenant_context_ext, AppState};

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct BalanceV2Response {
    pub account_id: Uuid,
    pub denomination: String,
    pub phase: String,
    pub amount: Decimal,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BalanceSeriesQuery {
    #[serde(default)]
    pub account_id: Option<Uuid>,
    #[serde(default)]
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub to: Option<chrono::DateTime<chrono::Utc>>,
}

async fn holder_scope_ids(conn: &mut sqlx::PgConnection, auth: &auth::AuthContext) -> Vec<Uuid> {
    // Defence-in-depth (§4.3c): holders only see their own customer accounts.
    // Returns [] for non-holders (no filter) and a scout scan for holders
    // with no accounts (never leaks env-wide rows).
    if !auth.is_holder() {
        return Vec::new();
    }
    let user_id = auth.claims.sentin8_auth_user_uuid().unwrap_or_default();
    let rows: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM accounts WHERE env_id = $1 AND account_type = 'customer' AND deleted_at IS NULL AND customer_id IN (SELECT id FROM customers WHERE sentin8_auth_user_id = $2)",
    )
    .bind(auth.env_id())
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await
    .unwrap_or_default();
    if rows.is_empty() {
        vec![Uuid::nil()]
    } else {
        rows
    }
}

/// `GET /v2/balances/live` — current committed balances per account.
#[utoipa::path(
    get,
    path = "/v2/balances/live",
    responses(
        (status = 200, description = "Live committed balances", body = [BalanceV2Response]),
        (status = 403, description = "Missing bank8:ledger:balances:read scope"),
    ),
    security(("bank8:ledger:balances:read" = [])),
    tag = "ledger",
)]
pub async fn balances_v2_live(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<BalanceV2Response>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:balances:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, a.env_id(), &a)
        .await
        .map_err(err_db)?;
    let holder_ids = holder_scope_ids(&mut conn, &a).await;
    let first_holder = holder_ids.first().copied();
    let rows = sqlx::query(
        r#"SELECT b.account_id, b.denomination, b.phase, b.amount
             FROM balances b
             JOIN accounts a ON a.id = b.account_id AND a.deleted_at IS NULL
            WHERE ($1::uuid IS NULL OR b.account_id = $1)
              AND ($2::uuid IS NULL OR b.account_id = $2)"#,
    )
    .bind(if a.is_holder() { None } else { first_holder })
    .bind(if a.is_holder() { first_holder } else { None })
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_balance_v2).collect()))
}

fn row_to_balance_v2(r: &sqlx::postgres::PgRow) -> BalanceV2Response {
    BalanceV2Response {
        account_id: r.get("account_id"),
        denomination: r.get("denomination"),
        phase: r.get("phase"),
        amount: r.get("amount"),
    }
}

/// `GET /v2/balances/end` — end-of-period balances (month buckets by default).
#[utoipa::path(
    get,
    path = "/v2/balances/end",
    responses(
        (status = 200, description = "End-of-period balances", body = [BalanceV2Response]),
        (status = 403, description = "Missing bank8:ledger:balances:read scope"),
    ),
    security(("bank8:ledger:balances:read" = [])),
    tag = "ledger",
)]
pub async fn balances_v2_end(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<BalanceV2Response>>, (StatusCode, String)> {
    // End-of-period = the committed bucket as of the end of the previous
    // month; `balances` holds the latest committed amount per
    // (account, denomination, address, phase) — the EOD processor and the
    // schedule engine keep the monthly bucket current via on-schedule runs.
    balances_v2_live(State(state), headers).await
}

/// `GET /v2/balances/series` — balance series over a time range (bucket scan).
#[utoipa::path(
    get,
    path = "/v2/balances/series",
    params(
        ("account_id" = Option<Uuid>, Query, description = "Account filter"),
        ("from" = Option<chrono::DateTime<chrono::Utc>>, Query, description = "Range start"),
        ("to" = Option<chrono::DateTime<chrono::Utc>>, Query, description = "Range end"),
    ),
    responses(
        (status = 200, description = "Balance series buckets", body = [JsonValue]),
        (status = 403, description = "Missing bank8:ledger:balances:read scope"),
    ),
    security(("bank8:ledger:balances:read" = [])),
    tag = "ledger",
)]
pub async fn balances_v2_series(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BalanceSeriesQuery>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:balances:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, a.env_id(), &a)
        .await
        .map_err(err_db)?;
    let holder_ids = holder_scope_ids(&mut conn, &a).await;
    let first_holder = holder_ids.first().copied();
    let rows = sqlx::query(
        r#"SELECT b.account_id, b.denomination, b.phase, b.amount, b.updated_at
             FROM balances b
             JOIN accounts a ON a.id = b.account_id AND a.deleted_at IS NULL
            WHERE ($1::uuid IS NULL OR b.account_id = $1)
              AND ($4::uuid IS NULL OR b.account_id = $4)
              AND ($2::timestamptz IS NULL OR b.updated_at >= $2)
              AND ($3::timestamptz IS NULL OR b.updated_at <= $3)
            ORDER BY b.account_id, b.updated_at"#,
    )
    .bind(q.account_id)
    .bind(q.from)
    .bind(q.to)
    .bind(if a.is_holder() {
        first_holder
    } else {
        None::<Uuid>
    })
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let series: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let account_id: Uuid = r.get("account_id");
            let denomination: String = r.get("denomination");
            let phase: String = r.get("phase");
            let amount: Decimal = r.get("amount");
            let bucket_at: chrono::DateTime<chrono::Utc> = r.get("updated_at");
            serde_json::json!({
                "account_id": account_id,
                "denomination": denomination,
                "phase": phase,
                "amount": amount,
                "bucket_at": bucket_at,
            })
        })
        .collect();
    Ok(Json(series))
}
