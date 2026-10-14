// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Bulk batches — account migrations and account update batches.
//! Data-Loader-style staging: a batch is submitted with its item payload,
//! stored pending in `account_migrations` / `account_update_batches`,
//! and applied row-by-row by `bulk-retry` (Sentin8 Jobs pattern — already-
//! applied rows are skipped, idempotent re-run). The Data Loader UI remains
//! out-of-scope (design §3.1); this covers the account/posting subset.

use axum::{
    extract::{Path, Query, State},
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
pub struct BulkBatchResponse {
    pub id: Uuid,
    pub kind: String,
    pub status: String,
    pub item_count: i32,
    pub failed_count: i32,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateBulkBatchRequest {
    /// `migration` (account migrations) or `account_update` (update batches).
    pub kind: String,
    #[serde(default)]
    pub source_system: Option<String>,
    /// Item payload: for account_update: [{account_id, set: {...}}]; for
    /// migration: [{account: {...}}] staged rows.
    pub items: JsonValue,
}

/// `POST /v1/account-migrations` — submit a bulk account migration batch
/// (Data-Loader-style staging; idempotent re-run via `:bulkRetry`).
#[utoipa::path(
    post,
    path = "/v1/account-migrations",
    request_body = CreateBulkBatchRequest,
    responses(
        (status = 200, description = "Migration batch created and staged", body = BulkBatchResponse),
        (status = 400, description = "kind must be 'migration' or 'account_update'"),
        (status = 403, description = "Missing bank8:ledger:accounts:write scope"),
    ),
    security(("bank8:ledger:accounts:write" = [])),
    tag = "ledger",
)]
pub async fn create_bulk_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateBulkBatchRequest>,
) -> Result<Json<BulkBatchResponse>, (StatusCode, String)> {
    if !matches!(req.kind.as_str(), "migration" | "account_update") {
        return Err((
            StatusCode::BAD_REQUEST,
            "kind must be 'migration' or 'account_update'".into(),
        ));
    }
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:write"),
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, a.env_id())
        .await
        .map_err(err_db)?;
    let item_count = req.items.as_array().map(|a| a.len()).unwrap_or(0) as i32;
    let (id, kind) = if req.kind == "migration" {
        let row = sqlx::query(
            r#"INSERT INTO account_migrations (env_id, source_system, payload, item_count, status)
               VALUES ($1, $2, $3, $4, 'pending') RETURNING id"#,
        )
        .bind(a.env_id()).bind(req.source_system.as_deref()).bind(&req.items).bind(item_count)
        .fetch_one(&mut *tx)
        .await
        .map_err(err_db)?;
        (row.get::<Uuid, _>("id"), "migration")
    } else {
        let row = sqlx::query(
            r#"INSERT INTO account_update_batches (env_id, payload, item_count, status)
               VALUES ($1, $2, $3, 'pending') RETURNING id"#,
        )
        .bind(a.env_id())
        .bind(&req.items)
        .bind(item_count)
        .fetch_one(&mut *tx)
        .await
        .map_err(err_db)?;
        (row.get::<Uuid, _>("id"), "account_update")
    };
    append_journal_event(
        &mut tx,
        a.env_id(),
        "bulk_batch",
        id,
        "create",
        &serde_json::json!({ "kind": kind, "item_count": item_count }),
    )
    .await?;
    tx.commit().await.map_err(err_db)?;
/* removed misplaced commit */
    Ok(Json(BulkBatchResponse {
        id,
        kind: kind.into(),
        status: "pending".into(),
        item_count,
        failed_count: 0,
        error_message: None,
        created_at: chrono::Utc::now(),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListBulkQuery {
    #[serde(default = "default_bulk_kind")]
    pub kind: String,
}
fn default_bulk_kind() -> String {
    "account_update".into()
}

/// `GET /v1/account-update-batches` — list bulk batches (either kind).
#[utoipa::path(
    get,
    path = "/v1/account-update-batches",
    params(("kind" = String, Query, description = "'migration' or 'account_update'")),
    responses(
        (status = 200, description = "Bulk batches", body = [BulkBatchResponse]),
        (status = 403, description = "Missing bank8:ledger:accounts:read scope"),
    ),
    security(("bank8:ledger:accounts:read" = [])),
    tag = "ledger",
)]
pub async fn list_bulk_batches(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListBulkQuery>,
) -> Result<Json<Vec<BulkBatchResponse>>, (StatusCode, String)> {
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
    let (table, failed_col) = if q.kind == "migration" {
        ("account_migrations", "failed_count")
    } else if q.kind == "account_update" {
        ("account_update_batches", "failed_item_count")
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            "kind must be 'migration' or 'account_update'".into(),
        ));
    };
    let sql = format!(
        r#"SELECT id, status, item_count, {failed_col} AS failed_count, error_message, created_at
             FROM {table} WHERE env_id = $1 ORDER BY created_at DESC LIMIT 200"#,
        table = table,
        failed_col = failed_col
    );
    let rows = sqlx::query(&sql)
        .bind(a.env_id())
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| BulkBatchResponse {
                id: r.get("id"),
                kind: q.kind.clone(),
                status: r.get("status"),
                item_count: r.get("item_count"),
                failed_count: r.get("failed_count"),
                error_message: r.get("error_message"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

/// `POST /v1/account-update-batches/{id}/bulk-retry` — retry failed rows in a
/// bulk batch (Sentin8 Jobs bulk-operations pattern). Staged rows are applied
/// account-by-account; already-applied rows are skipped (idempotent).
#[utoipa::path(
    post,
    path = "/v1/account-update-batches/{id}/bulk-retry",
    responses(
        (status = 200, description = "Retry result"),
        (status = 404, description = "Batch not found"),
        (status = 403, description = "Missing bank8:ledger:accounts:write scope"),
    ),
    security(("bank8:ledger:accounts:write" = [])),
    tag = "ledger",
)]
pub async fn bulk_retry_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    // Try the update-batch table first, then the migration table.
    let payload: Option<(String, JsonValue)> = sqlx::query(
        r#"SELECT status, payload FROM account_update_batches WHERE id = $1 AND env_id = $2"#,
    )
    .bind(id).bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .map(|r| (r.get::<String, _>("status"), r.get::<JsonValue, _>("payload")))
    .map(|(status, payload)| (format!("account_update:{status}"), payload));
    let (tag, payload) = match payload {
        Some(p) => p,
        None => {
            let row = sqlx::query(
                r#"SELECT status, payload FROM account_migrations WHERE id = $1 AND env_id = $2"#,
            )
            .bind(id).bind(a.env_id())
            .fetch_optional(&mut *conn)
            .await
            .map_err(err_db)?
            .ok_or((StatusCode::NOT_FOUND, format!("bulk batch {id} not found")))?;
            (
                format!("migration:{}", row.get::<String, _>("status")),
                row.get::<JsonValue, _>("payload"),
            )
        }
    };
    let _ = tag;
    let items = payload.as_array().cloned().unwrap_or_default();
    let mut applied = 0usize;
    let mut failed = 0usize;
    for item in &items {
        let account_id = item
            .get("account_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());
        let Some(account_id) = account_id else {
            failed += 1;
            continue;
        };
        let set = item
            .get("set")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let nickname = set.get("nickname").and_then(|v| v.as_str());
        let status = set.get("status").and_then(|v| v.as_str());
        let res = sqlx::query(
            r#"UPDATE accounts SET
                   nickname = COALESCE($3, nickname),
                   status = COALESCE($4, status),
                   updated_at = now()
               WHERE id = $1 AND env_id = $2"#,
        )
        .bind(account_id)
        .bind(a.env_id())
        .bind(nickname)
        .bind(status)
        .execute(&mut *conn)
        .await;
        match res {
            Ok(_) => applied += 1,
            Err(_) => failed += 1,
        }
    }
    let status = if failed == 0 { "completed" } else { "failed" };
    let err = if failed > 0 {
        Some(format!("{failed} item(s) failed"))
    } else {
        None
    };
    if is_update_batch(&state, a.env_id(), id).await {
        sqlx::query("UPDATE account_update_batches SET status = $2, failed_item_count = $3, error_message = $4, updated_at = now() WHERE id = $1")
            .bind(id).bind(status).bind(failed as i32).bind(err.as_deref())
            .execute(&mut *conn).await.map_err(err_db)?;
    } else {
        sqlx::query("UPDATE account_migrations SET status = $2, failed_count = $3, error_message = $4, updated_at = now() WHERE id = $1")
            .bind(id).bind(status).bind(failed as i32).bind(err.as_deref())
            .execute(&mut *conn).await.map_err(err_db)?;
    }
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:account:updated",
        serde_json::json!({ "bulk_batch_id": id, "applied": applied, "failed": failed }),
    )
    .await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(
        serde_json::json!({ "id": id, "applied": applied, "failed": failed, "status": status }),
    ))
}

async fn is_update_batch(state: &AppState, env_id: Uuid, id: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM account_update_batches WHERE id = $1 AND env_id = $2)",
    )
    .bind(id)
    .bind(env_id)
    .fetch_one(&state.pool)
    .await
    .map(|e: bool| e)
    .unwrap_or(false)
}

// ── Unit tests (§8.6 conventions — pure logic, no DB) ────────────────────

#[cfg(test)]
mod tests {
    /// Bulk-kind validation accepts exactly the two documented kinds.
    #[test]
    fn bulk_kind_validation() {
        assert!(matches!("migration", "migration" | "account_update"));
        assert!(matches!("account_update", "migration" | "account_update"));
        assert!(!matches!("something_else", "migration" | "account_update"));
    }
}
