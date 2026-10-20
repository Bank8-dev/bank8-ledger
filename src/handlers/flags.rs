// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Flag handlers - flag definitions and flags.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{err_db, set_tenant_context, AppState};

#[derive(ToSchema, Debug, serde::Serialize)]
pub struct FlagDefinitionResponse {
    pub id: Uuid,
    pub flag_name: String,
    pub required_flag_level: String,
    pub flag_visibility: String,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(ToSchema, Debug, Deserialize)]
pub struct CreateFlagDefinitionRequest {
    pub flag_name: String,
    #[serde(default = "default_account")]
    pub required_flag_level: String,
    #[serde(default = "default_private")]
    pub flag_visibility: String,
}

fn default_account() -> String {
    "ACCOUNT".into()
}
fn default_private() -> String {
    "PRIVATE".into()
}

#[utoipa::path(
    post,
    path = "/v1/flag-definitions",
    responses(
        (status = 200, description = "OK", body = FlagDefinitionResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
/// `POST /v1/flag-definitions` - create a flag definition.
pub async fn create_flag_definition(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateFlagDefinitionRequest>,
) -> Result<Json<FlagDefinitionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:write"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"INSERT INTO flag_definitions (env_id, flag_name, required_flag_level, flag_visibility)
           VALUES ($1, $2, $3, $4)
           RETURNING id, flag_name, required_flag_level, flag_visibility, is_active, created_at"#,
    )
    .bind(a.env_id())
    .bind(&req.flag_name)
    .bind(&req.required_flag_level)
    .bind(&req.flag_visibility)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let flag_def = row_to_flag_def(&row);
    super::emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:flagdefinition:created",
        serde_json::json!({ "flag_definition_id": flag_def.id }),
    )
    .await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(flag_def))
}

#[utoipa::path(
    get,
    path = "/v1/flag-definitions",
    responses(
        (status = 200, description = "OK", body = Vec<FlagDefinitionResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
/// `GET /v1/flag-definitions` - list flag definitions.
pub async fn list_flag_definitions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<FlagDefinitionResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT id, flag_name, required_flag_level, flag_visibility, is_active, created_at
             FROM flag_definitions ORDER BY created_at DESC"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_flag_def).collect()))
}

#[derive(ToSchema, Debug, serde::Serialize)]
pub struct FlagResponse {
    pub id: Uuid,
    pub flag_definition_id: Uuid,
    pub account_id: Option<Uuid>,
    pub customer_id: Option<Uuid>,
    pub value: String,
    pub effective_timestamp: chrono::DateTime<chrono::Utc>,
    pub expiry_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(ToSchema, Debug, Deserialize)]
pub struct CreateFlagRequest {
    pub flag_definition_id: Uuid,
    pub account_id: Option<Uuid>,
    pub customer_id: Option<Uuid>,
    #[serde(default = "default_on")]
    pub value: String,
    pub effective_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub expiry_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

fn default_on() -> String {
    "ON".into()
}

#[derive(Debug, Deserialize)]
pub struct ListFlagsQuery {
    #[serde(default)]
    pub account_id: Option<Uuid>,
    #[serde(default)]
    pub customer_id: Option<Uuid>,
    #[serde(default)]
    pub flag_definition_id: Option<Uuid>,
}

#[utoipa::path(
    post,
    path = "/v1/flags",
    responses(
        (status = 200, description = "OK", body = FlagDefinitionResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
/// `POST /v1/flags` - set a flag on an account or customer.
pub async fn create_flag(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateFlagRequest>,
) -> Result<Json<FlagResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:write"),
    )
    .await?;
    if req.account_id.is_none() && req.customer_id.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "account_id or customer_id is required".into(),
        ));
    }
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"INSERT INTO flags (env_id, flag_definition_id, account_id, customer_id, value, effective_timestamp, expiry_timestamp)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, flag_definition_id, account_id, customer_id, value, effective_timestamp, expiry_timestamp, created_at"#,
    )
    .bind(a.env_id()).bind(req.flag_definition_id)
    .bind(req.account_id).bind(req.customer_id).bind(&req.value)
    .bind(req.effective_timestamp.unwrap_or_else(chrono::Utc::now)).bind(req.expiry_timestamp)
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    let flag = row_to_flag(&row);
    super::emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:flag:created",
        serde_json::json!({ "flag_id": flag.id, "account_id": req.account_id }),
    )
    .await;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(flag))
}

#[utoipa::path(
    get,
    path = "/v1/flags",
    responses(
        (status = 200, description = "OK", body = Vec<FlagResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
/// `GET /v1/flags` - list flags.
pub async fn list_flags(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListFlagsQuery>,
) -> Result<Json<Vec<FlagResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT id, flag_definition_id, account_id, customer_id, value, effective_timestamp, expiry_timestamp, created_at
             FROM flags
            WHERE ($1::uuid IS NULL OR account_id = $1)
              AND ($2::uuid IS NULL OR customer_id = $2)
              AND ($3::uuid IS NULL OR flag_definition_id = $3)
            ORDER BY created_at DESC"#,
    )
    .bind(q.account_id).bind(q.customer_id).bind(q.flag_definition_id)
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_flag).collect()))
}

fn row_to_flag_def(row: &sqlx::postgres::PgRow) -> FlagDefinitionResponse {
    FlagDefinitionResponse {
        id: row.get("id"),
        flag_name: row.get("flag_name"),
        required_flag_level: row.get("required_flag_level"),
        flag_visibility: row.get("flag_visibility"),
        is_active: row.get("is_active"),
        created_at: row.get("created_at"),
    }
}

fn row_to_flag(row: &sqlx::postgres::PgRow) -> FlagResponse {
    FlagResponse {
        id: row.get("id"),
        flag_definition_id: row.get("flag_definition_id"),
        account_id: row.get("account_id"),
        customer_id: row.get("customer_id"),
        value: row.get("value"),
        effective_timestamp: row.get("effective_timestamp"),
        expiry_timestamp: row.get("expiry_timestamp"),
        created_at: row.get("created_at"),
    }
}
