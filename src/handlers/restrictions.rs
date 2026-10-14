// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Restriction handlers — restriction definitions and restriction sets.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{err_db, set_tenant_context, AppState};

#[derive(Debug, serde::Serialize)]
pub struct RestrictionDefinitionResponse {
    pub id: Uuid,
    pub action: String,
    pub description: Option<String>,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRestrictionDefinitionRequest {
    pub action: String,
    pub description: Option<String>,
}

/// `POST /v1/restriction-definitions` — create a restriction definition.
pub async fn create_restriction_definition(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateRestrictionDefinitionRequest>,
) -> Result<Json<RestrictionDefinitionResponse>, (StatusCode, String)> {
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
        r#"INSERT INTO restriction_definitions (env_id, action, description)
           VALUES ($1, $2, $3)
           RETURNING id, action, description, is_active, created_at"#,
    )
    .bind(a.env_id())
    .bind(&req.action)
    .bind(req.description.as_deref())
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let def = row_to_restriction_def(&row);
    super::emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:restrictiondefinition:created",
        serde_json::json!({ "restriction_definition_id": def.id }),
    )
    .await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(def))
}

/// `GET /v1/restriction-definitions` — list restriction definitions.
pub async fn list_restriction_definitions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<RestrictionDefinitionResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, action, description, is_active, created_at FROM restriction_definitions ORDER BY created_at DESC"#,
    )
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_restriction_def).collect()))
}

#[derive(Debug, serde::Serialize)]
pub struct RestrictionSetResponse {
    pub id: Uuid,
    pub restriction_definition_id: Uuid,
    pub account_id: Option<Uuid>,
    pub customer_id: Option<Uuid>,
    pub status: String,
    pub effective_timestamp: chrono::DateTime<chrono::Utc>,
    pub expiry_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRestrictionSetRequest {
    pub restriction_definition_id: Uuid,
    pub account_id: Option<Uuid>,
    pub customer_id: Option<Uuid>,
    pub expiry_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct ListRestrictionSetsQuery {
    #[serde(default)]
    pub account_id: Option<Uuid>,
    #[serde(default)]
    pub customer_id: Option<Uuid>,
}

/// `POST /v1/restriction-sets` — apply a restriction set to an account or customer.
pub async fn create_restriction_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateRestrictionSetRequest>,
) -> Result<Json<RestrictionSetResponse>, (StatusCode, String)> {
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
        r#"INSERT INTO restriction_sets (env_id, restriction_definition_id, account_id, customer_id, expiry_timestamp)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, restriction_definition_id, account_id, customer_id, status, effective_timestamp, expiry_timestamp, created_at"#,
    )
    .bind(a.env_id()).bind(req.restriction_definition_id)
    .bind(req.account_id).bind(req.customer_id).bind(req.expiry_timestamp)
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    let set = row_to_restriction_set(&row);
    super::emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:restrictionset:created",
        serde_json::json!({ "restriction_set_id": set.id, "account_id": req.account_id }),
    )
    .await;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(set))
}

/// `GET /v1/restriction-sets` — list restriction sets.
pub async fn list_restriction_sets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListRestrictionSetsQuery>,
) -> Result<Json<Vec<RestrictionSetResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, restriction_definition_id, account_id, customer_id, status, effective_timestamp, expiry_timestamp, created_at
             FROM restriction_sets
            WHERE ($1::uuid IS NULL OR account_id = $1)
              AND ($2::uuid IS NULL OR customer_id = $2)
            ORDER BY created_at DESC"#,
    )
    .bind(q.account_id).bind(q.customer_id)
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_restriction_set).collect()))
}

fn row_to_restriction_def(row: &sqlx::postgres::PgRow) -> RestrictionDefinitionResponse {
    RestrictionDefinitionResponse {
        id: row.get("id"),
        action: row.get("action"),
        description: row.get("description"),
        is_active: row.get("is_active"),
        created_at: row.get("created_at"),
    }
}

fn row_to_restriction_set(row: &sqlx::postgres::PgRow) -> RestrictionSetResponse {
    RestrictionSetResponse {
        id: row.get("id"),
        restriction_definition_id: row.get("restriction_definition_id"),
        account_id: row.get("account_id"),
        customer_id: row.get("customer_id"),
        status: row.get("status"),
        effective_timestamp: row.get("effective_timestamp"),
        expiry_timestamp: row.get("expiry_timestamp"),
        created_at: row.get("created_at"),
    }
}
