// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Product handlers — products, product versions, activation.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{err_db, set_tenant_context, AppState};

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct ProductResponse {
    pub id: Uuid,
    pub product_type: String,
    pub name: String,
    pub version: i32,
    pub status: String,
    pub parameters: serde_json::Value,
    pub modules: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateProductRequest {
    pub product_type: String,
    pub name: String,
    #[serde(default)]
    pub parameters: serde_json::Value,
    #[serde(default)]
    pub modules: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateProductRequest {
    pub name: Option<String>,
    pub parameters: Option<serde_json::Value>,
    pub modules: Option<serde_json::Value>,
}

/// `POST /v1/products` — create a product.
#[utoipa::path(
    post,
    path = "/v1/products",
    request_body = CreateProductRequest,
    responses(
        (status = 200, description = "Product created", body = ProductResponse),
        (status = 403, description = "Missing bank8:ledger:products:write scope"),
    ),
    security(("bank8:ledger:products:write" = [])),
    tag = "ledger",
)]
pub async fn create_product(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateProductRequest>,
) -> Result<Json<ProductResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:products:write")).await?;
    // Staff SSO tokens carry the STAFF env; the managed env comes from the
    // TLS-injected X-Sentin8-Env-Id header (Bank8:Admin is served at
    // bank8-admin.prod.{org}.{tld}). Same pattern as admin_ui.rs — see
    // resolve_org_env docs.
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await.map_err(err_db)?;
    let row = sqlx::query(
        r#"INSERT INTO products (env_id, product_type, name, parameters, modules)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, product_type, name, version, status, parameters, modules, created_at"#,
    )
    .bind(env_id).bind(&req.product_type).bind(&req.name)
    .bind(&req.parameters).bind(&req.modules)
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    let product = row_to_product(&row);
    super::emit_event(&state.pool, env_id, "bank8:ledger:product:created",
        serde_json::json!({ "product_id": product.id, "product_type": req.product_type }),
    ).await;
    conn.commit().await.map_err(err_db)?;

    Ok(Json(product))
}

/// `GET /v1/products` — list products.
#[utoipa::path(
    get,
    path = "/v1/products",
    responses(
        (status = 200, description = "List of products", body = [ProductResponse]),
        (status = 403, description = "Missing bank8:ledger:products:read scope"),
    ),
    security(("bank8:ledger:products:read" = [])),
    tag = "ledger",
)]
pub async fn list_products(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProductResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:products:read")).await?;
    // TLS-injected env wins over the token env — Bank8:Admin staff SSO
    // tokens carry the staff env but manage the prod env (see create_product).
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await.map_err(err_db)?;
    tracing::info!(%env_id, "bank8:ledger: list_products querying products");
    let rows = sqlx::query(
        r#"SELECT id, product_type, name, version, status, parameters, modules, created_at
             FROM products
             WHERE env_id = $1
             ORDER BY created_at DESC"#,
    )
    .bind(env_id)
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    tracing::info!(count = rows.len(), %env_id, "bank8:ledger: list_products returned");
    Ok(Json(rows.iter().map(row_to_product).collect()))
}

/// `GET /v1/products/{id}` — product detail.
#[utoipa::path(
    get,
    path = "/v1/products/{id}",
    params(("id" = Uuid, Path, description = "Product ID")),
    responses(
        (status = 200, description = "Product detail", body = ProductResponse),
        (status = 404, description = "Product not found"),
        (status = 403, description = "Missing bank8:ledger:products:read scope"),
    ),
    security(("bank8:ledger:products:read" = [])),
    tag = "ledger",
)]
pub async fn get_product(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ProductResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:products:read")).await?;
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await.map_err(err_db)?;
    let row = sqlx::query(
        r#"SELECT id, product_type, name, version, status, parameters, modules, created_at
             FROM products
             WHERE id = $1 AND env_id = $2"#,
    )
    .bind(id).bind(env_id)
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    Ok(Json(row_to_product(&row)))
}

/// `PUT /v1/products/{id}` — update product.
#[utoipa::path(
    put,
    path = "/v1/products/{id}",
    params(("id" = Uuid, Path, description = "Product ID")),
    request_body = UpdateProductRequest,
    responses(
        (status = 200, description = "Product updated", body = ProductResponse),
        (status = 403, description = "Missing bank8:ledger:products:write scope"),
    ),
    security(("bank8:ledger:products:write" = [])),
    tag = "ledger",
)]
pub async fn update_product(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateProductRequest>,
) -> Result<Json<ProductResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:products:write")).await?;
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await.map_err(err_db)?;
    let row = sqlx::query(
        r#"UPDATE products
              SET name = COALESCE($2, name),
                  parameters = COALESCE($3, parameters),
                  modules = COALESCE($4, modules),
                  updated_at = now()
            WHERE id = $1
            RETURNING id, product_type, name, version, status, parameters, modules, created_at"#,
    )
    .bind(id).bind(req.name.as_deref()).bind(req.parameters.as_ref()).bind(req.modules.as_ref())
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    let product = row_to_product(&row);
    super::emit_event(&state.pool, env_id, "bank8:ledger:product:updated",
        serde_json::json!({ "product_id": id }),
    ).await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(product))
}

/// `POST /v1/products/{id}/activate` — activate a product.
/// Also accepts `ledger:write` (broad write scope) for end-user app tokens.
#[utoipa::path(
    post,
    path = "/v1/products/{id}/activate",
    params(("id" = Uuid, Path, description = "Product ID")),
    responses(
        (status = 204, description = "Product activated"),
        (status = 403, description = "Missing bank8:ledger:products:publish scope"),
    ),
    security(("bank8:ledger:products:publish" = [])),
    tag = "ledger",
)]
pub async fn activate_product(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    // `products:publish` is the design §6 activation scope; callers holding
    // the broader `products:write` admin scope are also accepted (the scope
    // is nested in the ledger admin role).
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:products:publish")).await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await.map_err(err_db)?;
    sqlx::query("UPDATE products SET status = 'active', updated_at = now() WHERE id = $1")
        .bind(id).execute(&mut *conn).await.map_err(err_db)?;
    super::emit_event(&state.pool, a.env_id(), "bank8:ledger:product:activated",
        serde_json::json!({ "product_id": id }),
    ).await;
    conn.commit().await.map_err(err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Product Versions ──────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct ProductVersionResponse {
    pub id: Uuid,
    pub product_id: Uuid,
    pub version_number: i32,
    pub tside: String,
    pub contract_modules: serde_json::Value,
    pub supported_denominations: Vec<String>,
    pub parameters: serde_json::Value,
    pub expected_parameters: serde_json::Value,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateProductVersionRequest {
    pub tside: Option<String>,
    #[serde(default)]
    pub contract_modules: serde_json::Value,
    #[serde(default)]
    pub supported_denominations: Vec<String>,
    #[serde(default)]
    pub parameters: serde_json::Value,
    #[serde(default)]
    pub expected_parameters: serde_json::Value,
}

/// `POST /v1/products/{id}/versions` — create a product version.
#[utoipa::path(
    post,
    path = "/v1/products/{id}/versions",
    params(("id" = Uuid, Path, description = "Product ID")),
    request_body = CreateProductVersionRequest,
    responses(
        (status = 200, description = "Product version created", body = ProductVersionResponse),
        (status = 403, description = "Missing bank8:ledger:products:write scope"),
    ),
    security(("bank8:ledger:products:write" = [])),
    tag = "ledger",
)]
pub async fn create_product_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(product_id): Path<Uuid>,
    Json(req): Json<CreateProductVersionRequest>,
) -> Result<Json<ProductVersionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:products:write")).await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await.map_err(err_db)?;
    // Get next version number.
    let next_version: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version_number), 0) + 1 FROM product_versions_ext WHERE product_id = $1",
    )
    .bind(product_id).fetch_one(&mut *conn).await.unwrap_or(1);
    let tside = req.tside.unwrap_or_else(|| "LIABILITY".into());
    let row = sqlx::query(
        r#"INSERT INTO product_versions_ext
             (env_id, product_id, version_number, tside, contract_modules, supported_denominations, parameters, expected_parameters, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'draft')
           RETURNING id, product_id, version_number, tside, contract_modules, supported_denominations, parameters, expected_parameters, status, created_at"#,
    )
    .bind(a.env_id()).bind(product_id).bind(next_version).bind(&tside)
    .bind(&req.contract_modules).bind(&req.supported_denominations)
    .bind(&req.parameters).bind(&req.expected_parameters)
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    let version = row_to_version(&row);
    super::emit_event(&state.pool, a.env_id(), "bank8:ledger:productversion:created",
        serde_json::json!({ "product_id": product_id, "version_id": version.id }),
    ).await;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(version))
}

/// `GET /v1/products/{id}/versions` — list product versions.
#[utoipa::path(
    get,
    path = "/v1/products/{id}/versions",
    params(("id" = Uuid, Path, description = "Product ID")),
    responses(
        (status = 200, description = "List of product versions", body = [ProductVersionResponse]),
        (status = 403, description = "Missing bank8:ledger:products:read scope"),
    ),
    security(("bank8:ledger:products:read" = [])),
    tag = "ledger",
)]
pub async fn list_product_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(product_id): Path<Uuid>,
) -> Result<Json<Vec<ProductVersionResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:products:read")).await?;
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await.map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT id, product_id, version_number, tside, contract_modules, supported_denominations,
                  parameters, expected_parameters, status, created_at
             FROM product_versions_ext WHERE product_id = $1 ORDER BY version_number DESC"#,
    )
    .bind(product_id).fetch_all(&mut *conn).await.map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;

    Ok(Json(rows.iter().map(row_to_version).collect()))
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn row_to_product(row: &sqlx::postgres::PgRow) -> ProductResponse {
    ProductResponse {
        id: row.get("id"),
        product_type: row.get("product_type"),
        name: row.get("name"),
        version: row.get("version"),
        status: row.get("status"),
        parameters: row.get("parameters"),
        modules: row.get("modules"),
        created_at: row.get("created_at"),
    }
}

fn row_to_version(row: &sqlx::postgres::PgRow) -> ProductVersionResponse {
    ProductVersionResponse {
        id: row.get("id"),
        product_id: row.get("product_id"),
        version_number: row.get("version_number"),
        tside: row.get("tside"),
        contract_modules: row.get("contract_modules"),
        supported_denominations: row.get("supported_denominations"),
        parameters: row.get("parameters"),
        expected_parameters: row.get("expected_parameters"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }
}