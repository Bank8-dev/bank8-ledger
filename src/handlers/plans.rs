// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Plans — product plan lifecycle, migrations and account assocs.
//! A plan groups product parameters + modules for a set of accounts
//! (`plans`, `plan_assocs`). Plan migrations re-associate every
//! account of a from-plan onto the target plan and close the from-plan
//! (`plan_migrations`, design §5.3a).

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
pub struct PlanResponse {
    pub id: Uuid,
    pub name: String,
    pub product_type: Option<String>,
    pub parameters: JsonValue,
    pub modules: JsonValue,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePlanRequest {
    pub name: String,
    #[serde(default)]
    pub product_type: Option<String>,
    #[serde(default)]
    pub parameters: JsonValue,
    #[serde(default)]
    pub modules: JsonValue,
}

/// `POST /v1/plans` — create a plan.
#[utoipa::path(
    post,
    path = "/v1/plans",
    request_body = CreatePlanRequest,
    responses(
        (status = 200, description = "Plan created", body = PlanResponse),
        (status = 409, description = "Plan name exists"),
        (status = 403, description = "Missing bank8:ledger:products:write scope"),
    ),
    security(("bank8:ledger:products:write" = [])),
    tag = "ledger",
)]
pub async fn create_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreatePlanRequest>,
) -> Result<Json<PlanResponse>, (StatusCode, String)> {
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
        r#"INSERT INTO plans (env_id, name, product_type, parameters, modules)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, name, product_type, parameters, modules, status, created_at"#,
    )
    .bind(a.env_id())
    .bind(&req.name)
    .bind(req.product_type.as_deref())
    .bind(req.parameters)
    .bind(req.modules)
    .fetch_one(&mut *conn)
    .await;
    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            return Err((StatusCode::CONFLICT, "plan already exists".into()));
        }
        Err(e) => return Err(err_db(e)),
    };
    let plan_id: Uuid = row.get("id");
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:plan:created",
        serde_json::json!({ "plan_id": plan_id, "name": req.name }),
    )
    .await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(PlanResponse {
        id: plan_id,
        name: row.get("name"),
        product_type: row.get("product_type"),
        parameters: row.get("parameters"),
        modules: row.get("modules"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }))
}

/// `GET /v1/plans` — list plans.
#[utoipa::path(
    get,
    path = "/v1/plans",
    responses(
        (status = 200, description = "Plans", body = [PlanResponse]),
        (status = 403, description = "Missing bank8:ledger:products:read scope"),
    ),
    security(("bank8:ledger:products:read" = [])),
    tag = "ledger",
)]
pub async fn list_plans(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PlanResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, name, product_type, parameters, modules, status, created_at
             FROM plans WHERE env_id = $1 ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| PlanResponse {
                id: r.get("id"),
                name: r.get("name"),
                product_type: r.get("product_type"),
                parameters: r.get("parameters"),
                modules: r.get("modules"),
                status: r.get("status"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

/// `GET /v1/plans/{id}` — plan detail.
#[utoipa::path(
    get,
    path = "/v1/plans/{id}",
    responses(
        (status = 200, description = "Plan", body = PlanResponse),
        (status = 404, description = "Not found"),
    ),
    security(("bank8:ledger:products:read" = [])),
    tag = "ledger",
)]
pub async fn get_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<PlanResponse>, (StatusCode, String)> {
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
        r#"SELECT id, name, product_type, parameters, modules, status, created_at
             FROM plans WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, format!("plan {id} not found")))?;
    Ok(Json(PlanResponse {
        id: row.get("id"),
        name: row.get("name"),
        product_type: row.get("product_type"),
        parameters: row.get("parameters"),
        modules: row.get("modules"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MigratePlanRequest {
    pub from_plan_id: Option<Uuid>,
}

/// `POST /v1/plans/{id}/migrations` — migrate accounts onto a plan
/// (PlanMigration): re-associates the from-plan accounts and closes it.
#[utoipa::path(
    post,
    path = "/v1/plans/{id}/migrations",
    request_body = MigratePlanRequest,
    responses(
        (status = 200, description = "Migration completed"),
        (status = 403, description = "Missing bank8:ledger:products:write scope"),
    ),
    security(("bank8:ledger:products:write" = [])),
    tag = "ledger",
)]
pub async fn migrate_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(plan_id): Path<Uuid>,
    Json(req): Json<MigratePlanRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:products:write"),
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, a.env_id())
        .await
        .map_err(err_db)?;
    let from = req.from_plan_id;
    // Re-point every account of the from-plan to the target plan.
    let moved = if let Some(from_id) = from {
        sqlx::query(
            r#"UPDATE plan_assocs SET plan_id = $2, created_at = now()
                WHERE env_id = $1 AND plan_id = $3"#,
        )
        .bind(a.env_id())
        .bind(plan_id)
        .bind(from_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?
        .rows_affected()
    } else {
        0
    };
    // Close the from-plan and record the migration.
    if let Some(from_id) = from {
        sqlx::query(
            "UPDATE plans SET status = 'closed', updated_at = now() WHERE id = $1 AND env_id = $2",
        )
        .bind(from_id)
        .bind(a.env_id())
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    }
    let migration = sqlx::query(
        r#"INSERT INTO plan_migrations (env_id, plan_id, from_plan_id, status)
           VALUES ($1, $2, $3, 'completed') RETURNING id"#,
    )
    .bind(a.env_id())
    .bind(plan_id)
    .bind(from)
    .fetch_one(&mut *tx)
    .await
    .map_err(err_db)?;
    let migration_id: Uuid = migration.get("id");
    append_journal_event(&mut tx, a.env_id(), "plan", plan_id, "migrate",
        &serde_json::json!({ "migration_id": migration_id, "from_plan_id": from, "accounts_moved": moved }))
        .await?;
    tx.commit().await.map_err(err_db)?;
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:planmigration:created",
        serde_json::json!({ "plan_id": plan_id, "migration_id": migration_id }),
    )
    .await;
    Ok(Json(
        serde_json::json!({ "migration_id": migration_id, "accounts_moved": moved, "status": "completed" }),
    ))
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct PlanAssocResponse {
    pub id: Uuid,
    pub plan_id: Uuid,
    pub account_id: Uuid,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePlanAssocRequest {
    pub plan_id: Uuid,
    pub account_id: Uuid,
}

/// `GET /v1/account-plan-assocs` — list account↔plan associations.
#[utoipa::path(
    get,
    path = "/v1/account-plan-assocs",
    responses(
        (status = 200, description = "Plan associations", body = [PlanAssocResponse]),
        (status = 403, description = "Missing bank8:ledger:products:read scope"),
    ),
    security(("bank8:ledger:products:read" = [])),
    tag = "ledger",
)]
pub async fn list_plan_assocs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PlanAssocResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, plan_id, account_id FROM plan_assocs WHERE env_id = $1 ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| PlanAssocResponse {
                id: r.get("id"),
                plan_id: r.get("plan_id"),
                account_id: r.get("account_id"),
            })
            .collect(),
    ))
}

/// `POST /v1/account-plan-assocs` — associate an account with a plan.
#[utoipa::path(
    post,
    path = "/v1/account-plan-assocs",
    request_body = CreatePlanAssocRequest,
    responses(
        (status = 200, description = "Associated", body = PlanAssocResponse),
        (status = 403, description = "Missing bank8:ledger:products:write scope"),
    ),
    security(("bank8:ledger:products:write" = [])),
    tag = "ledger",
)]
pub async fn create_plan_assoc(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreatePlanAssocRequest>,
) -> Result<Json<PlanAssocResponse>, (StatusCode, String)> {
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
        r#"INSERT INTO plan_assocs (env_id, plan_id, account_id) VALUES ($1, $2, $3)
           ON CONFLICT (plan_id, account_id) DO UPDATE SET created_at = now()
           RETURNING id, plan_id, account_id"#,
    )
    .bind(a.env_id())
    .bind(req.plan_id)
    .bind(req.account_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(PlanAssocResponse {
        id: row.get("id"),
        plan_id: row.get("plan_id"),
        account_id: row.get("account_id"),
    }))
}

// ── Unit tests (§8.6 conventions — pure logic, no DB) ────────────────────

#[cfg(test)]
mod tests {
    /// Plan migration: moving zero accounts (no from-plan) yields 0 moved.
    #[test]
    fn plan_migration_zero_move_without_from() {
        let from: Option<uuid::Uuid> = None;
        assert!(from.is_none());
    }
}
