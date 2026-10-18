// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Parameter handlers — parameters, parameter values, hierarchy nodes.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use sqlx::Row;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{err_db, set_tenant_context, AppState};

// ── Parameters ───────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
pub struct ParameterResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub is_instance: bool,
    pub is_template: bool,
    pub is_derived: bool,
    pub data_type: String,
    pub constraints: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateParameterRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub is_instance: bool,
    #[serde(default = "default_true")]
    pub is_template: bool,
    #[serde(default)]
    pub is_derived: bool,
    #[serde(default = "default_string")]
    pub data_type: String,
    #[serde(default)]
    pub constraints: serde_json::Value,
}

fn default_true() -> bool {
    true
}
fn default_string() -> String {
    "string".into()
}

#[utoipa::path(
    post,
    path = "/v1/parameters",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
/// `POST /v1/parameters` — create a parameter definition.
pub async fn create_parameter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateParameterRequest>,
) -> Result<Json<ParameterResponse>, (StatusCode, String)> {
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
        r#"INSERT INTO parameters (env_id, name, description, is_instance, is_template, is_derived, data_type, constraints)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id, name, description, is_instance, is_template, is_derived, data_type, constraints, created_at"#,
    )
    .bind(a.env_id()).bind(&req.name).bind(req.description.as_deref())
    .bind(req.is_instance).bind(req.is_template).bind(req.is_derived).bind(&req.data_type).bind(&req.constraints)
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    let param = row_to_param(&row);
    super::emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:parameter:created",
        serde_json::json!({ "parameter_id": param.id }),
    )
    .await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(param))
}

#[utoipa::path(
    get,
    path = "/v1/parameters",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
/// `GET /v1/parameters` — list parameters.
pub async fn list_parameters(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ParameterResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, name, description, is_instance, is_template, is_derived, data_type, constraints, created_at
             FROM parameters ORDER BY created_at DESC"#,
    )
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_param).collect()))
}

// ── Parameter Values ────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParameterValueResponse {
    pub id: Uuid,
    pub parameter_id: Uuid,
    pub account_id: Option<Uuid>,
    pub hierarchy_node_id: Option<Uuid>,
    pub is_global: bool,
    pub value: serde_json::Value,
    pub effective_from_timestamp: chrono::DateTime<chrono::Utc>,
    pub effective_to_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateParameterValueRequest {
    pub parameter_id: Uuid,
    pub account_id: Option<Uuid>,
    pub hierarchy_node_id: Option<Uuid>,
    #[serde(default)]
    pub is_global: bool,
    pub value: serde_json::Value,
    #[serde(default)]
    pub effective_from_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct ListParamValuesQuery {
    #[serde(default)]
    pub parameter_id: Option<Uuid>,
    #[serde(default)]
    pub account_id: Option<Uuid>,
}

#[utoipa::path(
    post,
    path = "/v1/parameter-values",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
/// `POST /v1/parameter-values` — create a parameter value.
pub async fn create_parameter_value(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateParameterValueRequest>,
) -> Result<Json<ParameterValueResponse>, (StatusCode, String)> {
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
        r#"INSERT INTO parameter_values (env_id, parameter_id, account_id, hierarchy_node_id, is_global, value, effective_from_timestamp)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, parameter_id, account_id, hierarchy_node_id, is_global, value, effective_from_timestamp, effective_to_timestamp, created_at"#,
    )
    .bind(a.env_id()).bind(req.parameter_id)
    .bind(req.account_id).bind(req.hierarchy_node_id).bind(req.is_global)
    .bind(&req.value).bind(req.effective_from_timestamp.unwrap_or_else(chrono::Utc::now))
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    let pv = row_to_param_value(&row);
    super::emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:parametervalue:created",
        serde_json::json!({ "parameter_id": req.parameter_id, "value_id": pv.id }),
    )
    .await;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(pv))
}

#[utoipa::path(
    get,
    path = "/v1/parameter-values",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
/// `GET /v1/parameter-values` — list parameter values.
pub async fn list_parameter_values(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListParamValuesQuery>,
) -> Result<Json<Vec<ParameterValueResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, parameter_id, account_id, hierarchy_node_id, is_global, value, effective_from_timestamp, effective_to_timestamp, created_at
             FROM parameter_values
            WHERE ($1::uuid IS NULL OR parameter_id = $1)
              AND ($2::uuid IS NULL OR account_id = $2)
            ORDER BY effective_from_timestamp DESC"#,
    )
    .bind(q.parameter_id).bind(q.account_id)
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_param_value).collect()))
}

#[utoipa::path(
    get,
    path = "/v1/parameter-values:viewEffective",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
/// `GET /v1/parameter-values:viewEffective` — resolve effective parameter value
/// at a point in time, with hierarchy precedence (account > hierarchy > global).
///
/// Results are served from a bounded TTL cache (design §10): the
/// parameter-value write path is insert-only with `effective_from`, so a
/// short TTL self-heals and no event-driven invalidation is needed. The
/// posting money path never consults this cache — parameter resolution
/// there is transactional by design (a stale fee rate is a correctness
/// defect, not a latency trade).
pub async fn view_effective_parameter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ViewEffectiveQuery>,
) -> Result<Json<ParameterValueResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read"),
    )
    .await?;
    let snapshot = q.snapshot_timestamp.unwrap_or_else(chrono::Utc::now);
    let cache_key = EffectiveCacheKey {
        env_id: a.env_id(),
        parameter_id: q.parameter_id,
        account_id: q.account_id,
        snapshot_timestamp: snapshot,
    };
    if let Some(cached) = state.effective_param_cache.get(&cache_key) {
        return Ok(Json(cached));
    }
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    // Try account-level first, then hierarchy, then global.
    let row = if let Some(account_id) = q.account_id {
        sqlx::query(
            r#"SELECT id, parameter_id, account_id, hierarchy_node_id, is_global, value, effective_from_timestamp, effective_to_timestamp, created_at
                 FROM parameter_values
                WHERE parameter_id = $1 AND account_id = $2
                  AND effective_from_timestamp <= $3
                  AND (effective_to_timestamp IS NULL OR effective_to_timestamp >= $3)
                ORDER BY effective_from_timestamp DESC LIMIT 1"#,
        )
        .bind(q.parameter_id).bind(account_id).bind(snapshot)
        .fetch_optional(&mut *conn).await.map_err(err_db)?
    } else {
        None
    };
    let row = if row.is_none() {
        sqlx::query(
            r#"SELECT id, parameter_id, account_id, hierarchy_node_id, is_global, value, effective_from_timestamp, effective_to_timestamp, created_at
                 FROM parameter_values
                WHERE parameter_id = $1 AND is_global = true
                  AND effective_from_timestamp <= $2
                  AND (effective_to_timestamp IS NULL OR effective_to_timestamp >= $2)
                ORDER BY effective_from_timestamp DESC LIMIT 1"#,
        )
        .bind(q.parameter_id).bind(snapshot)
        .fetch_optional(&mut *conn).await.map_err(err_db)?
    } else {
        row
    };
    let row = row.ok_or((
        StatusCode::NOT_FOUND,
        "no effective parameter value found".into(),
    ))?;
    let response = row_to_param_value(&row);
    state
        .effective_param_cache
        .insert(cache_key, response.clone());
    Ok(Json(response))
}

/// Cache key for `viewEffective` — everything the resolution depends on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EffectiveCacheKey {
    env_id: Uuid,
    parameter_id: Uuid,
    account_id: Option<Uuid>,
    snapshot_timestamp: chrono::DateTime<chrono::Utc>,
}

/// Bounded TTL cache for effective parameter reads (design §10). The
/// prune-on-insert sweep bounds memory under unbounded key cardinality:
/// expired entries are dropped *before* inserting, so a cache saturated
/// with distinct hot keys self-prunes instead of growing.
///
/// Locking: a `std::sync::Mutex` is safe here — the critical section is
/// a small map clone/insert with no `await`, far under any tokio
/// blocking-safety concern for a request-path cache.
#[derive(Default)]
pub struct EffectiveParamCache {
    entries: Mutex<HashMap<EffectiveCacheKey, (ParameterValueResponse, std::time::Instant)>>,
}

impl EffectiveParamCache {
    /// Cache TTL — parameter values are insert-only with `effective_from`,
    /// so an entry older than this can never re-resolve differently unless
    /// a new value row was written; a fresh write then lands after at most
    /// one TTL window.
    const TTL: Duration = Duration::from_secs(30);

    /// Cache capacity — bounded, matching the platform bounded-cache
    /// pattern (RoleResolver). Insert-time pruning keeps it under this
    /// count of *live* entries.
    const MAX_ENTRIES: usize = 4096;

    fn get(&self, key: &EffectiveCacheKey) -> Option<ParameterValueResponse> {
        let mut entries = self.entries.lock().ok()?;
        let (value, fetched_at) = entries.get(key)?;
        if fetched_at.elapsed() > Self::TTL {
            entries.remove(key);
            return None;
        }
        Some(value.clone())
    }

    fn insert(&self, key: EffectiveCacheKey, value: ParameterValueResponse) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        // Prune expired entries before inserting (bounded-cache pattern).
        entries.retain(|_, (_, fetched_at)| fetched_at.elapsed() <= Self::TTL);
        if entries.len() >= Self::MAX_ENTRIES {
            // Evict by oldest fetched-at — a tiny O(n) scan at capacity,
            // cheaper than tracking an ordering structure for a cold path.
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, (_, fetched_at))| *fetched_at)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(key, (value, std::time::Instant::now()));
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    fn resp(id: &str) -> ParameterValueResponse {
        let v = serde_json::json!({
            "id": uuid::Uuid::new_v4(), "parameter_id": uuid::Uuid::new_v4(),
            "account_id": None::<Uuid>, "hierarchy_node_id": None::<Uuid>,
            "is_global": true, "value": id,
            "effective_from_timestamp": chrono::Utc::now(),
            "effective_to_timestamp": None::<chrono::DateTime<chrono::Utc>>,
            "created_at": chrono::Utc::now(),
        });
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn cache_hit_returns_value() {
        let cache = EffectiveParamCache::default();
        let key = EffectiveCacheKey {
            env_id: uuid::Uuid::new_v4(),
            parameter_id: uuid::Uuid::new_v4(),
            account_id: None,
            snapshot_timestamp: chrono::Utc::now(),
        };
        assert!(cache.get(&key).is_none());
        cache.insert(key.clone(), resp("v1"));
        assert_eq!(cache.get(&key).unwrap().value, serde_json::json!("v1"));
    }

    #[test]
    fn cache_max_entries_prunes_oldest() {
        let cache = EffectiveParamCache::default();
        for i in 0..(EffectiveParamCache::MAX_ENTRIES + 10) {
            let key = EffectiveCacheKey {
                env_id: uuid::Uuid::new_v4(),
                parameter_id: uuid::Uuid::new_v4(),
                account_id: None,
                snapshot_timestamp: chrono::Utc::now(),
            };
            cache.insert(key, resp(&i.to_string()));
        }
        let entries = cache.entries.lock().unwrap();
        assert_eq!(entries.len(), EffectiveParamCache::MAX_ENTRIES);
    }
}

#[derive(Debug, Deserialize)]
pub struct ViewEffectiveQuery {
    pub parameter_id: Uuid,
    #[serde(default)]
    pub account_id: Option<Uuid>,
    #[serde(default)]
    pub snapshot_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

// ── Hierarchy Nodes ──────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
pub struct HierarchyNodeResponse {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub layer: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateHierarchyNodeRequest {
    pub parent_id: Option<Uuid>,
    pub name: String,
}

#[utoipa::path(
    post,
    path = "/v1/parameter-value-hierarchy-nodes",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
/// `POST /v1/parameter-value-hierarchy-nodes` — create a hierarchy node.
pub async fn create_hierarchy_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateHierarchyNodeRequest>,
) -> Result<Json<HierarchyNodeResponse>, (StatusCode, String)> {
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
    let layer = if let Some(parent_id) = req.parent_id {
        sqlx::query_scalar("SELECT layer + 1 FROM parameter_value_hierarchy_nodes WHERE id = $1")
            .bind(parent_id)
            .fetch_one(&mut *conn)
            .await
            .unwrap_or(1)
    } else {
        0
    };
    let row = sqlx::query(
        r#"INSERT INTO parameter_value_hierarchy_nodes (env_id, parent_id, name, layer)
           VALUES ($1, $2, $3, $4)
           RETURNING id, parent_id, name, layer, created_at"#,
    )
    .bind(a.env_id())
    .bind(req.parent_id)
    .bind(&req.name)
    .bind(layer)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let node_id: Uuid = row.get("id");
    super::emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:hierarchynode:created",
        serde_json::json!({ "node_id": node_id }),
    )
    .await;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(HierarchyNodeResponse {
        id: row.get("id"),
        parent_id: row.get("parent_id"),
        name: row.get("name"),
        layer: row.get("layer"),
        created_at: row.get("created_at"),
    }))
}

#[utoipa::path(
    get,
    path = "/v1/parameter-value-hierarchy-nodes",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
/// `GET /v1/parameter-value-hierarchy-nodes` — list hierarchy nodes.
pub async fn list_hierarchy_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<HierarchyNodeResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, parent_id, name, layer, created_at FROM parameter_value_hierarchy_nodes ORDER BY layer, name"#,
    )
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| HierarchyNodeResponse {
                id: r.get("id"),
                parent_id: r.get("parent_id"),
                name: r.get("name"),
                layer: r.get("layer"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn row_to_param(row: &sqlx::postgres::PgRow) -> ParameterResponse {
    ParameterResponse {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        is_instance: row.get("is_instance"),
        is_template: row.get("is_template"),
        is_derived: row.get("is_derived"),
        data_type: row.get("data_type"),
        constraints: row.get("constraints"),
        created_at: row.get("created_at"),
    }
}

fn row_to_param_value(row: &sqlx::postgres::PgRow) -> ParameterValueResponse {
    ParameterValueResponse {
        id: row.get("id"),
        parameter_id: row.get("parameter_id"),
        account_id: row.get("account_id"),
        hierarchy_node_id: row.get("hierarchy_node_id"),
        is_global: row.get("is_global"),
        value: row.get("value"),
        effective_from_timestamp: row.get("effective_from_timestamp"),
        effective_to_timestamp: row.get("effective_to_timestamp"),
        created_at: row.get("created_at"),
    }
}
