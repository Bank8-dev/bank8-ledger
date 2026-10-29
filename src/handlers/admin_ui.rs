// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Bank8:Ledger Admin UI handlers - RFW (Remote Flutter Widget) definitions.
//! Each handler returns an `AdminUiPage` (or `AdminUiResponse`) that Sentin8:Dash
//! fetches via `GET /v1/admin/ui/{page}` and renders at runtime.
//! See `sentin8-architecture-principles.md` §4.15 for the full Remote UI architecture.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::policy_pages::AdminDataRows;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;
use serde::Deserialize;
use sqlx::Row;

use crate::handlers::AppState;

#[derive(Debug, Deserialize, Default)]
pub struct AdminUiQuery {
    pub r#type: Option<String>,
}

#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    responses(
        (status = 200, description = "OK", body = sentin8::rfw::AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// GET /v1/admin/ui/{page} - return RFW definition for the requested admin page.
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
    Query(q): Query<AdminUiQuery>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    // Step 5 - Shield decides (principles §5.2, policy design §4.3). UI
    // definitions carry no data; the scope-mirror set permits read actions
    // per-scope, and platform/org/env admin scopes ride the same live-scope
    // evaluation (the platform set permits them for read actions too).
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read"),
    )
    .await?;

    // NOTE: no seeding here. Seeding is event-driven only (env-init via
    // Sentin8:Bus `sentin8:sys:service:updated`) - a GET must never mutate
    // data, and seeding the *caller's* env let staff tokens create internal
    // accounts in feature-disabled envs (incident 2026-08-28).

    let page_def = match page.as_str() {
        "overview" => overview_page(),
        "accounts" => accounts_page(),
        "postings" => postings_page(),
        "products" => products_page(),
        "products/new" => {
            // Stage 1: product type selection (no ?type= param)
            // Stage 2: type-specific config form (?type=current_account)
            if let Some(ref pt) = q.r#type {
                product_create_config_page(&state.pool, &headers, a.env_id(), pt).await
            } else {
                product_type_selection_page()
            }
        }
        // Product detail/edit/versions are handled dynamically - the page
        // name includes the product ID (e.g. "products/abc-123/edit").
        // These are matched by prefix below.
        "schedules" => schedules_page(),
        "jobs" => jobs_page(),
        "dlq" => dlq_page(),
        "reconcile" => reconcile_page(),
        "balances" => balances_page(),
        "parameters" => parameters_page(),
        "parameters/new" => parameter_create_page(),
        "restrictions" => restrictions_page(),
        "restrictions/new" => restriction_create_page(),
        "flags" => flags_page(),
        "flags/new" => flag_create_page(),
        "customers" => customers_page(),
        "statements" => statements_page(),
        "settings" => settings_page(),
        // ── Policy Studio (design §3.7, story 28.14) - shared page
        // constructors; the guard guarantees `Some` (§3.7 dispatch).
        p if sentin8::rfw::policy_page("bank8:ledger", p).is_some() => {
            sentin8::rfw::policy_page("bank8:ledger", p)
                .expect("policy_page checked in guard")
                .build()
        }
        _ => {
            // Dynamic routes: products/{id}, products/{id}/edit, products/{id}/versions, products/{id}/versions/new
            if page.starts_with("products/") {
                let parts: Vec<&str> = page.split('/').collect();
                if parts.len() == 2 {
                    product_detail_page(parts[1])
                } else if parts.len() == 3 && parts[2] == "edit" {
                    product_edit_page(parts[1])
                } else if parts.len() == 3 && parts[2] == "versions" {
                    product_versions_page(parts[1])
                } else if parts.len() == 4 && parts[2] == "versions" && parts[3] == "new" {
                    product_version_create_page(parts[1])
                } else {
                    return Err((
                        axum::http::StatusCode::NOT_FOUND,
                        format!("Unknown admin UI page: {page}"),
                    ));
                }
            } else {
                return Err((
                    axum::http::StatusCode::NOT_FOUND,
                    format!("Unknown admin UI page: {page}"),
                ));
            }
        }
    };

    Ok(Json(AdminUiResponse::page(page_def)))
}

#[utoipa::path(
    post,
    path = "/v1/admin/products",
    responses(
        (status = 200, description = "RFW page/ack response", body = AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// `POST /v1/admin/products` - handle product creation form submission.
/// Called by the RFW form renderer when the user clicks "Create Product".
/// Creates the product and returns an `AdminUiResponse::redirect` so the
/// RFW renderer navigates back to the products list.
pub async fn submit_product_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    use crate::auth;
    use crate::handlers::set_tenant_context;
    use sqlx::Row;
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:products:write"),
    )
    .await?;
    let name = body["name"].as_str().unwrap_or("").trim();
    let product_type = body["product_type"]
        .as_str()
        .unwrap_or("current_account")
        .trim();
    if name.is_empty() {
        return Ok(Json(AdminUiResponse::error("Product name is required")));
    }
    // Parse modules - the form sends a comma-separated string or array.
    let modules: serde_json::Value = if let Some(arr) = body["modules"].as_array() {
        serde_json::Value::Array(arr.clone())
    } else if let Some(s) = body["modules"].as_str() {
        if s.is_empty() || s == "[]" {
            serde_json::Value::Array(vec![])
        } else {
            serde_json::from_str(s).unwrap_or(serde_json::Value::Array(vec![]))
        }
    } else {
        serde_json::Value::Array(vec![])
    };
    // Parse parameters - collect all param_* fields from the form body.
    let mut params_obj = serde_json::Map::new();
    if let Some(obj) = body.as_object() {
        for (key, val) in obj {
            if let Some(param_key) = key.strip_prefix("param_") {
                if let Some(s) = val.as_str() {
                    if !s.is_empty() {
                        params_obj.insert(param_key.into(), serde_json::Value::String(s.into()));
                    }
                }
            }
        }
    }
    // Also accept a direct parameters JSON object (for backward compatibility).
    if let Some(s) = body["parameters"].as_str() {
        if let Ok(extra) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(s) {
            for (k, v) in extra {
                params_obj.insert(k, v);
            }
        }
    } else if let Some(extra) = body["parameters"].as_object() {
        for (k, v) in extra {
            params_obj.insert(k.clone(), v.clone());
        }
    }
    // Merge denomination into parameters if provided.
    if let Some(denom) = body["denomination"].as_str() {
        params_obj.insert(
            "denomination".into(),
            serde_json::Value::String(denom.into()),
        );
    }
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // TLS-injected env wins over the token env - staff SSO tokens carry the
    // staff env but Bank8:Admin manages the env the browser is on
    // (bank8-admin.prod.{org}.{tld} → X-Sentin8-Env-Id = prod env).
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    set_tenant_context(&mut conn, env_id)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row = sqlx::query(
        r#"INSERT INTO products (env_id, product_type, name, parameters, modules)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id"#,
    )
    .bind(env_id)
    .bind(product_type)
    .bind(name)
    .bind(serde_json::Value::Object(params_obj))
    .bind(&modules)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let product_id: uuid::Uuid = row.get("id");

    conn.commit()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tracing::info!(product_id = %product_id, %name, %product_type, "admin_ui: product created via form");
    // Redirect to the product detail page.
    Ok(Json(AdminUiResponse::redirect(format!(
        "products/{product_id}"
    ))))
}

#[utoipa::path(
    put,
    path = "/v1/admin/products/{id}",
    responses(
        (status = 200, description = "RFW page/ack response", body = AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// `PUT /v1/admin/products/{id}` - handle product edit form submission.
pub async fn submit_product_edit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    use crate::auth;
    use crate::handlers::set_tenant_context;
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:products:write"),
    )
    .await?;
    let name = body["name"].as_str().unwrap_or("").trim();
    if name.is_empty() {
        return Ok(Json(AdminUiResponse::error("Product name is required")));
    }
    let modules: serde_json::Value = if let Some(arr) = body["modules"].as_array() {
        serde_json::Value::Array(arr.clone())
    } else if let Some(s) = body["modules"].as_str() {
        serde_json::from_str(s).unwrap_or(serde_json::Value::Array(vec![]))
    } else {
        serde_json::Value::Array(vec![])
    };
    let parameters: serde_json::Value = if let Some(s) = body["parameters"].as_str() {
        serde_json::from_str(s).unwrap_or(serde_json::Value::Object(Default::default()))
    } else if body["parameters"].is_object() {
        body["parameters"].clone()
    } else {
        serde_json::Value::Object(Default::default())
    };
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    set_tenant_context(&mut conn, env_id)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query(
        r#"UPDATE products SET name = $2, parameters = $3, modules = $4, updated_at = now()
           WHERE id = $1"#,
    )
    .bind(id)
    .bind(name)
    .bind(&parameters)
    .bind(&modules)
    .execute(&mut *conn)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tracing::info!(product_id = %id, "admin_ui: product updated via form");

    conn.commit()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AdminUiResponse::redirect(format!("products/{id}"))))
}

#[utoipa::path(
    post,
    path = "/v1/admin/products/{id}/versions",
    responses(
        (status = 200, description = "RFW page/ack response", body = AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// `POST /v1/admin/products/{id}/versions` - create a new product version.
pub async fn submit_product_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    use crate::auth;
    use crate::handlers::set_tenant_context;
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:products:write"),
    )
    .await?;
    let tside = body["tside"].as_str().unwrap_or("LIABILITY");
    let supported_denoms: Vec<String> = if let Some(s) = body["supported_denominations"].as_str() {
        s.split(',')
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty())
            .collect()
    } else if let Some(arr) = body["supported_denominations"].as_array() {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect()
    } else {
        vec![]
    };
    let contract_modules: serde_json::Value = if let Some(s) = body["contract_modules"].as_str() {
        serde_json::from_str(s).unwrap_or(serde_json::Value::Array(vec![]))
    } else {
        body["contract_modules"].clone()
    };
    let parameters: serde_json::Value = if let Some(s) = body["parameters"].as_str() {
        serde_json::from_str(s).unwrap_or(serde_json::Value::Object(Default::default()))
    } else {
        body["parameters"].clone()
    };
    let expected_parameters: serde_json::Value =
        if let Some(s) = body["expected_parameters"].as_str() {
            serde_json::from_str(s).unwrap_or(serde_json::Value::Array(vec![]))
        } else {
            body["expected_parameters"].clone()
        };

    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    set_tenant_context(&mut conn, env_id)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Auto-increment version number.
    let max_version: i32 = sqlx::query_scalar(
        r#"SELECT COALESCE(MAX(version_number), 0) FROM product_versions_ext WHERE product_id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn).await
    .unwrap_or(0);
    let _ = sqlx::query(
        r#"INSERT INTO product_versions_ext
           (env_id, product_id, version_number, tside, contract_modules, supported_denominations, parameters, expected_parameters, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'draft')"#,
    )
    .bind(env_id).bind(id)
    .bind(max_version + 1).bind(tside).bind(&contract_modules)
    .bind(&supported_denoms).bind(&parameters).bind(&expected_parameters)
    .execute(&mut *conn).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tracing::info!(product_id = %id, version = max_version + 1, "admin_ui: product version created via form");

    conn.commit()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AdminUiResponse::redirect(format!("products/{id}"))))
}

// ── Admin form submissions - non-product resources (RECON-5) ────────────

fn form_str(body: &serde_json::Value, key: &str) -> Option<String> {
    body[key]
        .as_str()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn form_uuid(body: &serde_json::Value, key: &str) -> Option<uuid::Uuid> {
    form_str(body, key).and_then(|s| uuid::Uuid::parse_str(&s).ok())
}

#[utoipa::path(
    post,
    path = "/v1/admin/accounts",
    responses(
        (status = 200, description = "RFW page/ack response", body = AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// `POST /v1/admin/accounts` - create-account form submission.
pub async fn submit_account_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    use crate::handlers::set_tenant_context;
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:write"),
    )
    .await?;
    let account_type = form_str(&body, "account_type").unwrap_or_else(|| "customer".into());
    if !matches!(account_type.as_str(), "customer" | "internal") {
        return Ok(Json(AdminUiResponse::error(
            "account_type must be customer|internal",
        )));
    }
    let customer_id = form_uuid(&body, "customer_id");
    let product_id = form_uuid(&body, "product_id");
    if account_type == "customer" && customer_id.is_none() {
        return Ok(Json(AdminUiResponse::error(
            "customer_id is required for customer accounts",
        )));
    }
    let denomination = form_str(&body, "denomination").unwrap_or_else(|| "CAD".into());
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    set_tenant_context(&mut conn, env_id)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row = sqlx::query(
        r#"INSERT INTO accounts (env_id, customer_id, product_id, account_type, product_type, nickname, denomination, status)
           VALUES ($1, $2, $3, $4,
                   (SELECT product_type FROM products WHERE id = $3 AND env_id = $1),
                   $5, $6, 'active')
           RETURNING id"#,
    )
    .bind(env_id).bind(customer_id).bind(product_id)
    .bind(&account_type).bind(form_str(&body, "nickname").as_deref()).bind(&denomination)
    .fetch_one(&mut *conn).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let account_id: uuid::Uuid = row.get("id");
    tracing::info!(account_id = %account_id, "admin_ui: account created via form");
    super::emit_event(&state.pool, env_id, "bank8:ledger:account:created",
        serde_json::json!({ "account_id": account_id, "product_id": product_id, "customer_id": customer_id }),
    ).await;

    conn.commit()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AdminUiResponse::redirect("accounts".to_string())))
}

#[utoipa::path(
    put,
    path = "/v1/admin/accounts/{id}",
    responses(
        (status = 200, description = "RFW page/ack response", body = AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// `PUT /v1/admin/accounts/{id}` - update-account form submission.
pub async fn submit_account_edit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    use crate::handlers::set_tenant_context;
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:write"),
    )
    .await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    set_tenant_context(&mut conn, env_id)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    sqlx::query(
        r#"UPDATE accounts
              SET nickname = COALESCE($2, nickname),
                  status = COALESCE($3, status),
                  closed_at = CASE WHEN $3 = 'CLOSED' THEN now() ELSE closed_at END,
                  updated_at = now()
            WHERE id = $1 AND env_id = $4 AND deleted_at IS NULL"#,
    )
    .bind(id)
    .bind(form_str(&body, "nickname").as_deref())
    .bind(form_str(&body, "status").as_deref())
    .bind(env_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tracing::info!(account_id = %id, "admin_ui: account updated via form");

    conn.commit()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AdminUiResponse::redirect("accounts")))
}

/// Acknowledgement after an admin posting form submission (typed body).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct AdminPostingAck {
    /// The RFW route to navigate back to.
    pub redirect: String,
    /// The created posting instruction id.
    pub posting_id: uuid::Uuid,
    /// The accepted posting status.
    pub status: String,
}

#[utoipa::path(
    post,
    path = "/v1/admin/postings",
    responses(
        (status = 200, description = "RFW page/ack response", body = AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// `POST /v1/admin/postings` - new-posting form submission (batch of one).
pub async fn submit_posting_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<AdminPostingAck>, (axum::http::StatusCode, String)> {
    // create_posting re-checks the scope; the pre-check here surfaces auth
    // failures before field validation for cleaner admin error messages.
    let _a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:write"),
    )
    .await?;
    let debit = form_uuid(&body, "debit_account_id").ok_or((
        axum::http::StatusCode::BAD_REQUEST,
        "debit_account_id required".into(),
    ))?;
    let credit = form_uuid(&body, "credit_account_id").ok_or((
        axum::http::StatusCode::BAD_REQUEST,
        "credit_account_id required".into(),
    ))?;
    let amount = form_str(&body, "amount").ok_or((
        axum::http::StatusCode::BAD_REQUEST,
        "amount required".into(),
    ))?;
    let denomination = form_str(&body, "currency").unwrap_or_else(|| "CAD".into());
    let req = crate::handlers::postings::CreatePostingRequest {
        batch_id: format!("admin-{}", uuid::Uuid::new_v4()),
        idempotency_key: None,
        dry_run: false,
        instructions: vec![crate::handlers::postings::PostingInstruction {
            instruction_type: form_str(&body, "instruction_type")
                .unwrap_or_else(|| "TRANSFER".into()),
            debit_account: debit,
            credit_account: credit,
            amount,
            denomination,
            value_timestamp: None,
            description: form_str(&body, "reference"),
        }],
    };
    // Reuse the domain handler (same scope check - fine for admin callers).
    let resp =
        crate::handlers::postings::create_posting(State(state), headers, axum::Json(req)).await?;
    Ok(Json(AdminPostingAck {
        redirect: "postings".into(),
        posting_id: resp.0.id,
        status: resp.0.status,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/admin/parameters",
    responses(
        (status = 200, description = "RFW page/ack response", body = AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// `POST /v1/admin/parameters` - create-parameter form submission.
pub async fn submit_parameter_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    use crate::handlers::set_tenant_context;
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:write"),
    )
    .await?;
    let name = form_str(&body, "name").ok_or((
        axum::http::StatusCode::BAD_REQUEST,
        "parameter name required".into(),
    ))?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    set_tenant_context(&mut conn, env_id)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    sqlx::query(
        r#"INSERT INTO parameters (env_id, name, description, is_instance, is_template, is_derived, data_type, constraints)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
    )
    .bind(env_id).bind(&name).bind(form_str(&body, "description").as_deref())
    .bind(body["is_instance"].as_bool().unwrap_or(false))
    .bind(body["is_template"].as_bool().unwrap_or(true))
    .bind(body["is_derived"].as_bool().unwrap_or(false))
    .bind(form_str(&body, "data_type").unwrap_or_else(|| "string".into()))
    .bind(body["constraints"].as_str()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .unwrap_or_else(|| serde_json::json!({})))
    .execute(&mut *conn).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tracing::info!(%name, "admin_ui: parameter created via form");

    conn.commit()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AdminUiResponse::redirect("parameters")))
}

#[utoipa::path(
    post,
    path = "/v1/admin/restriction-sets",
    responses(
        (status = 200, description = "RFW page/ack response", body = AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// `POST /v1/admin/restriction-sets` - create-restriction form submission.
pub async fn submit_restriction_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    use crate::handlers::set_tenant_context;
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:write"),
    )
    .await?;
    let definition_id = form_uuid(&body, "restriction_definition_id").ok_or((
        axum::http::StatusCode::BAD_REQUEST,
        "restriction_definition_id required".into(),
    ))?;
    let account_id = form_uuid(&body, "account_id");
    let customer_id = form_uuid(&body, "customer_id");
    if account_id.is_none() && customer_id.is_none() {
        return Ok(Json(AdminUiResponse::error(
            "Provide either an Account ID or Customer ID",
        )));
    }
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    set_tenant_context(&mut conn, env_id)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    sqlx::query(
        r#"INSERT INTO restriction_sets (env_id, restriction_definition_id, account_id, customer_id, expiry_timestamp)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(env_id).bind(definition_id).bind(account_id).bind(customer_id)
    .bind(form_str(&body, "expiry_timestamp").and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&chrono::Utc)))
    .execute(&mut *conn).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tracing::info!(
        ?account_id,
        ?customer_id,
        "admin_ui: restriction set created via form"
    );

    conn.commit()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AdminUiResponse::redirect("restrictions")))
}

#[utoipa::path(
    post,
    path = "/v1/admin/flags",
    responses(
        (status = 200, description = "RFW page/ack response", body = AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// `POST /v1/admin/flags` - create-flag form submission.
pub async fn submit_flag_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    use crate::handlers::set_tenant_context;
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:write"),
    )
    .await?;
    let definition_id = form_uuid(&body, "flag_definition_id").ok_or((
        axum::http::StatusCode::BAD_REQUEST,
        "flag_definition_id required".into(),
    ))?;
    let account_id = form_uuid(&body, "account_id");
    let customer_id = form_uuid(&body, "customer_id");
    if account_id.is_none() && customer_id.is_none() {
        return Ok(Json(AdminUiResponse::error(
            "Provide either an Account ID or Customer ID",
        )));
    }
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    set_tenant_context(&mut conn, env_id)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    sqlx::query(
        r#"INSERT INTO flags (env_id, flag_definition_id, account_id, customer_id, value, effective_timestamp)
           VALUES ($1, $2, $3, $4, $5, now())"#,
    )
    .bind(env_id).bind(definition_id).bind(account_id).bind(customer_id)
    .bind(form_str(&body, "value").unwrap_or_else(|| "ON".into()))
    .execute(&mut *conn).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tracing::info!(?account_id, "admin_ui: flag created via form");

    conn.commit()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AdminUiResponse::redirect("flags")))
}

#[utoipa::path(
    post,
    path = "/v1/admin/dlq/{id}/discard",
    responses(
        (status = 200, description = "RFW page/ack response", body = AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// `POST /v1/admin/dlq/{id}/discard` - discard a DLQ entry (no republish).
pub async fn discard_dlq_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    use crate::handlers::{err_db, set_tenant_context};
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:dlq:republish"),
    )
    .await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let result = sqlx::query("DELETE FROM dlq WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(err_db)?;
    if result.rows_affected() == 0 {
        return Ok(Json(AdminUiResponse::error("DLQ entry not found")));
    }
    tracing::info!(dlq_id = %id, "admin_ui: DLQ entry discarded");

    conn.commit()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AdminUiResponse::redirect("dlq")))
}

// ── Registration-declared data endpoints (RECON-5) ──────────────────────

/// Reconciliation totals for the admin postings view (typed body).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct AdminReconcileSummary {
    /// Total posting batches in the ledger.
    pub total_batches: i64,
    /// Batches in `accepted` state.
    pub accepted: i64,
    /// Batches in `rejected` state.
    pub rejected: i64,
    /// Entries currently parked in the DLQ.
    pub dlq_entries: i64,
}

#[utoipa::path(
    get,
    path = "/v1/admin/reconcile",
    responses(
        (status = 200, description = "Reconciliation summary", body = AdminReconcileSummary),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// `GET /v1/admin/reconcile` - reconciliation summary (posting totals).
pub async fn admin_reconcile_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminReconcileSummary>, (axum::http::StatusCode, String)> {
    use crate::handlers::set_tenant_context;
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:read"),
    )
    .await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    set_tenant_context(&mut conn, env_id)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let total_batches: i64 = sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM postings")
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let accepted: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM postings WHERE status = 'accepted'")
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let rejected: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM postings WHERE status = 'rejected'")
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let dlq: i64 = sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM dlq")
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AdminReconcileSummary {
        total_batches,
        accepted,
        rejected,
        dlq_entries: dlq,
    }))
}

#[utoipa::path(
    get,
    path = "/v1/admin/balances",
    responses(
        (status = 200, description = "RFW page/ack response", body = AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// `GET /v1/admin/balances` - account balances view (RFW DataTable rows).
pub async fn admin_balances(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminDataRows>, (axum::http::StatusCode, String)> {
    use crate::handlers::set_tenant_context;
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:balances:read"),
    )
    .await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    set_tenant_context(&mut conn, env_id)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let rows = sqlx::query(
        r#"SELECT b.account_id, COALESCE(a.nickname, a.product_type, '') AS account_name,
                  b.denomination,
                  COALESCE(SUM(CASE WHEN b.phase = 'COMMITTED' THEN b.amount END), 0) AS committed,
                  COALESCE(SUM(CASE WHEN b.phase = 'PENDING_IN' THEN b.amount END), 0) AS pending,
                  COALESCE(SUM(CASE WHEN b.phase IN ('COMMITTED', 'PENDING_IN') THEN b.amount END), 0) AS available
             FROM balances b
             LEFT JOIN accounts a ON a.id = b.account_id
            WHERE b.address = 'DEFAULT'
            GROUP BY b.account_id, a.nickname, b.denomination
            ORDER BY b.account_id
            LIMIT 200"#,
    )
    .fetch_all(&mut *conn).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let out: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "account_id": r.get::<uuid::Uuid, _>("account_id"),
                "account_name": r.get::<Option<String>, _>("account_name").unwrap_or_default(),
                "denomination": r.get::<Option<String>, _>("denomination"),
                "committed": r.get::<rust_decimal::Decimal, _>("committed"),
                "pending": r.get::<rust_decimal::Decimal, _>("pending"),
                "available": r.get::<rust_decimal::Decimal, _>("available"),
            })
        })
        .collect();
    Ok(Json(AdminDataRows::Items { items: out }))
}

/// Ledger runtime settings shown on the admin settings page (typed body).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct AdminSettings {
    /// The service identifier.
    pub service: String,
    /// The configured stream family.
    pub stream_family: String,
    /// The default money denomination.
    pub default_denomination: String,
    /// The database connection-pool cap.
    pub pool_cap: i32,
}

#[utoipa::path(
    get,
    path = "/v1/admin/settings",
    responses(
        (status = 200, description = "RFW page/ack response", body = AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// `GET /v1/admin/settings` - static ledger settings payload.
pub async fn admin_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminSettings>, (axum::http::StatusCode, String)> {
    // Step 5 - Shield decides (principles §5.2, policy design §4.3). The
    // scope-mirror set permits this read action per-scope; platform-admin /
    // org-admin / env-admin scopes carry read permits the same way.
    let _a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read"),
    )
    .await?;
    Ok(Json(AdminSettings {
        service: "bank8:ledger".into(),
        stream_family: state.config.stream_family.clone(),
        default_denomination: "CAD".into(),
        pool_cap: 3,
    }))
}

#[utoipa::path(
    get,
    path = "/v1/admin/statements",
    responses(
        (status = 200, description = "RFW page/ack response", body = AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
/// `GET /v1/admin/statements` - recent statements (RFW DataTable rows).
pub async fn admin_statements(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminDataRows>, (axum::http::StatusCode, String)> {
    use crate::handlers::set_tenant_context;
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read"),
    )
    .await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let env_id = crate::handlers::resolve_org_env(&headers, uuid::Uuid::nil(), a.env_id());
    set_tenant_context(&mut conn, env_id)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let rows = sqlx::query(
        r#"SELECT id, account_id, period_start, period_end, document_url, document_format, created_at
             FROM statements ORDER BY period_start DESC LIMIT 100"#,
    )
    .fetch_all(&mut *conn).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let out: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<uuid::Uuid, _>("id"),
                "account_id": r.get::<uuid::Uuid, _>("account_id"),
                "period_start": r.get::<chrono::DateTime<chrono::Utc>, _>("period_start"),
                "period_end": r.get::<chrono::DateTime<chrono::Utc>, _>("period_end"),
                "document_url": r.get::<Option<String>, _>("document_url"),
                "document_format": r.get::<String, _>("document_format"),
                "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            })
        })
        .collect();
    Ok(Json(AdminDataRows::Items { items: out }))
}

// ── Page definitions ──

fn overview_page() -> AdminUiPage {
    AdminPage::new("Ledger Overview")
        .widget(RemoteWidget::Card(WidgetCard {
            title: Some("Summary".into()),
            subtitle: None,
            children: vec![RemoteWidget::Text(WidgetText {
                text: "Product catalog, accounts, posting console, schedules, DLQ, reconciliation."
                    .into(),
                text_type: WidgetTextType::Body,
                align: TextAlign::Left,
                max_lines: None,
            })],
            actions: vec![],
        }))
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Account ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Name".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "type".into(),
                    label: "Type".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "balance".into(),
                    label: "Balance".into(),
                    sortable: true,
                    width: None,
                    format: Some("currency".into()),
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/accounts".into(),
            sortable: true,
            filterable: true,
            page_size: 20,
            empty_message: Some("No accounts found.".into()),
            row_link: Some("/ledger/accounts/{id}".into()),
            row_actions: vec![],
        }))
        .build()
}

fn accounts_page() -> AdminUiPage {
    AdminPage::new("Accounts")
        .action(AdminUiAction {
            label: "Create Account".into(),
            action_type: crate::handlers::admin_ui::AdminUiActionType::Link,
            route: Some("accounts/new".into()),
            endpoint: None,
            icon: Some("0xe145".into()),
        })
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Account ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Name".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "type".into(),
                    label: "Type".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "balance".into(),
                    label: "Balance".into(),
                    sortable: true,
                    width: None,
                    format: Some("currency".into()),
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/accounts".into(),
            sortable: true,
            filterable: true,
            page_size: 20,
            empty_message: Some("No accounts found.".into()),
            row_link: Some("/ledger/accounts/{id}".into()),
            row_actions: vec![],
        }))
        .build()
}

fn postings_page() -> AdminUiPage {
    AdminPage::new("Postings")
        .widget(RemoteWidget::Card(WidgetCard {
            title: Some("New Posting".into()),
            subtitle: None,
            children: vec![RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "debit_account_id".into(),
                        label: "Debit Account".into(),
                        field_type: FormFieldType::Select,
                        required: true,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "credit_account_id".into(),
                        label: "Credit Account".into(),
                        field_type: FormFieldType::Select,
                        required: true,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "amount".into(),
                        label: "Amount".into(),
                        field_type: FormFieldType::Decimal,
                        required: true,
                        placeholder: Some("0.00".into()),
                        default_value: None,
                        options: None,
                        validation: Some(FormFieldValidation {
                            min: Some(0.01),
                            max: None,
                            pattern: None,
                            min_length: None,
                            max_length: None,
                            custom_message: None,
                        }),
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "currency".into(),
                        label: "Currency".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("USD".into()),
                        default_value: Some(serde_json::Value::String("USD".into())),
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "reference".into(),
                        label: "Reference".into(),
                        field_type: FormFieldType::Text,
                        required: false,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/admin/postings".into(),
                submit_label: "Submit Posting".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            })],
            actions: vec![],
        }))
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Batch ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "created_at".into(),
                    label: "Created".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
            ],
            data_endpoint: "/postings".into(),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No postings found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn products_page() -> AdminUiPage {
    AdminPage::new("Products")
        .action(AdminUiAction {
            label: "Create Product".into(),
            action_type: AdminUiActionType::Link,
            route: Some("products/new".into()),
            endpoint: None,
            icon: Some("0xe145".into()),
        })
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Product ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Name".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "product_type".into(),
                    label: "Type".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/products".into(),
            sortable: true,
            filterable: true,
            page_size: 20,
            empty_message: Some("No products found.".into()),
            row_link: Some("/ledger/products/{id}".into()),
            row_actions: vec![],
        }))
        .build()
}

// ── Product Type Selection (Stage 1) ──

/// Product type metadata for the selection grid.
struct ProductParamDefault {
    key: &'static str,
    label: &'static str,
    default: &'static str,
    help: &'static str,
    /// Determines the input widget: "number", "decimal", "percentage", "integer", "select", "boolean", "text"
    param_type: &'static str,
    /// For select fields: comma-separated options
    options: &'static str,
}

struct ProductTypeInfo {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    tside: &'static str,
    denominations: &'static [&'static str],
    default_modules: &'static [&'static str],
    default_params: &'static [ProductParamDefault],
}

const PRODUCT_TYPES: &[ProductTypeInfo] = &[
    ProductTypeInfo {
        id: "current_account",
        name: "Current Account",
        description: "Everyday transactional account with optional overdraft",
        tside: "LIABILITY",
        denominations: &["CAD", "USD", "EUR", "GBP"],
        default_modules: &[
            "denomination-validation",
            "deposit-limits",
            "withdrawal-limits",
            "maximum-balance",
            "deposit-interest-accrual",
            "deposit-interest-application",
            "minimum-balance-fee",
            "maintenance-fees",
            "inactivity-fee",
            "dormancy",
        ],
        default_params: &[
            ProductParamDefault {
                key: "interest_rate",
                label: "Interest Rate",
                default: "0.001",
                help: "Annual interest rate (e.g. 0.001 = 0.1%)",
                param_type: "percentage",
                options: "",
            },
            ProductParamDefault {
                key: "overdraft_limit",
                label: "Overdraft Limit",
                default: "500",
                help: "Maximum overdraft amount in denomination currency",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "monthly_maintenance_fee",
                label: "Monthly Maintenance Fee",
                default: "5.00",
                help: "Monthly account maintenance fee",
                param_type: "decimal",
                options: "",
            },
            ProductParamDefault {
                key: "inactivity_fee",
                label: "Inactivity Fee",
                default: "2.00",
                help: "Fee charged after inactivity period",
                param_type: "decimal",
                options: "",
            },
            ProductParamDefault {
                key: "maximum_balance",
                label: "Maximum Balance",
                default: "1000000",
                help: "Maximum allowed account balance",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "interest_application_frequency",
                label: "Interest Application Frequency",
                default: "monthly",
                help: "How often interest is applied",
                param_type: "select",
                options: "daily,monthly,quarterly,annually",
            },
            ProductParamDefault {
                key: "interest_paid_account",
                label: "Interest Paid Account",
                default: "",
                help: "Ledger account ID for interest paid (debit side)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "interest_received_account",
                label: "Interest Received Account",
                default: "",
                help: "Ledger account ID for interest received (income)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "accrued_interest_payable_account",
                label: "Accrued Interest Payable Account",
                default: "",
                help: "Ledger account ID for accrued interest payable",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "monthly_maintenance_fee_income_account",
                label: "Monthly Fee Income Account",
                default: "",
                help: "Ledger account ID for monthly maintenance fee income",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "inactivity_fee_income_account",
                label: "Inactivity Fee Income Account",
                default: "",
                help: "Ledger account ID for inactivity fee income",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "minimum_balance_fee_income_account",
                label: "Min Balance Fee Income Account",
                default: "",
                help: "Ledger account ID for minimum balance fee income",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "excess_fee_income_account",
                label: "Excess Fee Income Account",
                default: "",
                help: "Ledger account ID for withdrawal excess fee income",
                param_type: "text",
                options: "",
            },
        ],
    },
    ProductTypeInfo {
        id: "savings_account",
        name: "Savings Account",
        description: "Interest-earning deposit account with tiered rates",
        tside: "LIABILITY",
        denominations: &["CAD", "USD", "EUR", "GBP"],
        default_modules: &[
            "denomination-validation",
            "deposit-limits",
            "withdrawal-limits",
            "maximum-balance",
            "deposit-interest-accrual",
            "deposit-interest-application",
            "minimum-balance-fee",
            "inactivity-fee",
            "dormancy",
        ],
        default_params: &[
            ProductParamDefault {
                key: "interest_rate",
                label: "Interest Rate",
                default: "0.02",
                help: "Annual interest rate (e.g. 0.02 = 2%)",
                param_type: "percentage",
                options: "",
            },
            ProductParamDefault {
                key: "minimum_balance",
                label: "Minimum Balance",
                default: "100",
                help: "Minimum balance to avoid fees",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "maximum_balance",
                label: "Maximum Balance",
                default: "5000000",
                help: "Maximum allowed account balance",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "interest_application_frequency",
                label: "Interest Application Frequency",
                default: "monthly",
                help: "How often interest is applied",
                param_type: "select",
                options: "daily,monthly,quarterly,annually",
            },
            ProductParamDefault {
                key: "inactivity_fee",
                label: "Inactivity Fee",
                default: "1.00",
                help: "Fee charged after inactivity period",
                param_type: "decimal",
                options: "",
            },
            ProductParamDefault {
                key: "interest_paid_account",
                label: "Interest Paid Account",
                default: "",
                help: "Ledger account ID for interest paid (debit side)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "interest_received_account",
                label: "Interest Received Account",
                default: "",
                help: "Ledger account ID for interest received (income)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "accrued_interest_payable_account",
                label: "Accrued Interest Payable Account",
                default: "",
                help: "Ledger account ID for accrued interest payable",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "inactivity_fee_income_account",
                label: "Inactivity Fee Income Account",
                default: "",
                help: "Ledger account ID for inactivity fee income",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "minimum_balance_fee_income_account",
                label: "Min Balance Fee Income Account",
                default: "",
                help: "Ledger account ID for minimum balance fee income",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "excess_fee_income_account",
                label: "Excess Fee Income Account",
                default: "",
                help: "Ledger account ID for withdrawal excess fee income",
                param_type: "text",
                options: "",
            },
        ],
    },
    ProductTypeInfo {
        id: "credit_card",
        name: "Credit Card",
        description: "Payment card with configurable transaction types and statement cycles",
        tside: "ASSET",
        denominations: &["CAD", "USD", "EUR", "GBP"],
        default_modules: &["maintenance-fees", "overlimit-fees", "late-repayment-fees"],
        default_params: &[
            ProductParamDefault {
                key: "credit_limit",
                label: "Credit Limit",
                default: "5000",
                help: "Maximum credit limit (> 0)",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "annual_percentage_rate",
                label: "Annual Percentage Rate",
                default: "0.1899",
                help: "APR (e.g. 0.1899 = 18.99%)",
                param_type: "percentage",
                options: "",
            },
            ProductParamDefault {
                key: "annual_fee",
                label: "Annual Fee",
                default: "0",
                help: "Annual card fee",
                param_type: "decimal",
                options: "",
            },
            ProductParamDefault {
                key: "late_repayment_fee",
                label: "Late Repayment Fee",
                default: "25",
                help: "Fee for late payments",
                param_type: "decimal",
                options: "",
            },
            ProductParamDefault {
                key: "overlimit_fee",
                label: "Overlimit Fee",
                default: "25",
                help: "Fee for exceeding credit limit",
                param_type: "decimal",
                options: "",
            },
            ProductParamDefault {
                key: "payment_due_period",
                label: "Payment Due Period (days)",
                default: "25",
                help: "Days from statement to payment due date",
                param_type: "integer",
                options: "",
            },
            ProductParamDefault {
                key: "minimum_percentage_due",
                label: "Minimum Percentage Due",
                default: "0.03",
                help: "Minimum payment as fraction of balance",
                param_type: "percentage",
                options: "",
            },
            ProductParamDefault {
                key: "interest_received_account",
                label: "Interest Received Account",
                default: "",
                help: "Ledger account ID for interest received (income)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "late_repayment_fee_internal_account",
                label: "Late Fee Income Account",
                default: "",
                help: "Ledger account ID for late repayment fee income",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "overlimit_fee_internal_account",
                label: "Overlimit Fee Income Account",
                default: "",
                help: "Ledger account ID for overlimit fee income",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "annual_fee_internal_account",
                label: "Annual Fee Income Account",
                default: "",
                help: "Ledger account ID for annual fee income",
                param_type: "text",
                options: "",
            },
        ],
    },
    ProductTypeInfo {
        id: "loan",
        name: "Loan",
        description: "Personal loan with amortised repayments and interest",
        tside: "ASSET",
        denominations: &["CAD", "USD", "EUR", "GBP"],
        default_modules: &["deposit-interest-accrual", "deposit-interest-application"],
        default_params: &[
            ProductParamDefault {
                key: "fixed_interest_rate",
                label: "Fixed Interest Rate",
                default: "0.0899",
                help: "Annual interest rate (e.g. 0.0899 = 8.99%)",
                param_type: "percentage",
                options: "",
            },
            ProductParamDefault {
                key: "amortisation_method",
                label: "Amortisation Method",
                default: "straight_line",
                help: "Amortisation method",
                param_type: "select",
                options: "straight_line,reducing_balance",
            },
            ProductParamDefault {
                key: "repayment_period",
                label: "Repayment Period (months)",
                default: "36",
                help: "Loan term in months",
                param_type: "integer",
                options: "",
            },
            ProductParamDefault {
                key: "due_amount_calculation_day",
                label: "Due Amount Calculation Day",
                default: "1",
                help: "Day of month for repayment (1-28)",
                param_type: "integer",
                options: "",
            },
            ProductParamDefault {
                key: "grace_period",
                label: "Grace Period (days)",
                default: "5",
                help: "Grace period before late fee",
                param_type: "integer",
                options: "",
            },
            ProductParamDefault {
                key: "late_repayment_fee",
                label: "Late Repayment Fee",
                default: "15",
                help: "Fee for late repayment",
                param_type: "decimal",
                options: "",
            },
            ProductParamDefault {
                key: "early_repayment_fee_rate",
                label: "Early Repayment Fee Rate",
                default: "0.01",
                help: "Fee rate for early repayment",
                param_type: "percentage",
                options: "",
            },
            ProductParamDefault {
                key: "interest_received_account",
                label: "Interest Received Account",
                default: "",
                help: "Ledger account ID for interest received (income)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "accrued_interest_receivable_account",
                label: "Accrued Interest Receivable Account",
                default: "",
                help: "Ledger account ID for accrued interest receivable",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "late_repayment_fee_income_account",
                label: "Late Fee Income Account",
                default: "",
                help: "Ledger account ID for late repayment fee income",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "upfront_fee_income_account",
                label: "Upfront Fee Income Account",
                default: "",
                help: "Ledger account ID for upfront fee income",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "penalty_interest_received_account",
                label: "Penalty Interest Received Account",
                default: "",
                help: "Ledger account ID for penalty interest received",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "early_repayment_fee_income_account",
                label: "Early Repayment Fee Income Account",
                default: "",
                help: "Ledger account ID for early repayment fee income",
                param_type: "text",
                options: "",
            },
        ],
    },
    ProductTypeInfo {
        id: "mortgage",
        name: "Mortgage",
        description: "Secured property loan with fixed/variable rate periods",
        tside: "ASSET",
        denominations: &["CAD", "USD", "EUR", "GBP", "AUD"],
        default_modules: &["deposit-interest-accrual", "deposit-interest-application"],
        default_params: &[
            ProductParamDefault {
                key: "fixed_interest_rate",
                label: "Fixed Interest Rate",
                default: "0.0599",
                help: "Annual interest rate during fixed period",
                param_type: "percentage",
                options: "",
            },
            ProductParamDefault {
                key: "is_fixed_interest",
                label: "Is Fixed Interest",
                default: "true",
                help: "Whether the loan has a fixed interest period",
                param_type: "boolean",
                options: "",
            },
            ProductParamDefault {
                key: "fixed_interest_term",
                label: "Fixed Interest Term (months)",
                default: "60",
                help: "Length of fixed interest period",
                param_type: "integer",
                options: "",
            },
            ProductParamDefault {
                key: "loan_term_months",
                label: "Loan Term (months)",
                default: "360",
                help: "Total loan term (> 0)",
                param_type: "integer",
                options: "",
            },
            ProductParamDefault {
                key: "due_amount_calculation_day",
                label: "Due Amount Calculation Day",
                default: "1",
                help: "Day of month for repayment (1-28)",
                param_type: "integer",
                options: "",
            },
            ProductParamDefault {
                key: "grace_period",
                label: "Grace Period (days)",
                default: "15",
                help: "Grace period before late fee",
                param_type: "integer",
                options: "",
            },
            ProductParamDefault {
                key: "late_repayment_fee",
                label: "Late Repayment Fee",
                default: "50",
                help: "Fee for late repayment",
                param_type: "decimal",
                options: "",
            },
            ProductParamDefault {
                key: "amortisation_method",
                label: "Amortisation Method",
                default: "straight_line",
                help: "Amortisation method",
                param_type: "select",
                options: "straight_line,reducing_balance",
            },
            ProductParamDefault {
                key: "interest_received_account",
                label: "Interest Received Account",
                default: "",
                help: "Ledger account ID for interest received (income)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "accrued_interest_receivable_account",
                label: "Accrued Interest Receivable Account",
                default: "",
                help: "Ledger account ID for accrued interest receivable",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "late_repayment_fee_income_account",
                label: "Late Fee Income Account",
                default: "",
                help: "Ledger account ID for late repayment fee income",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "penalty_interest_received_account",
                label: "Penalty Interest Received Account",
                default: "",
                help: "Ledger account ID for penalty interest received",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "early_repayment_fee_income_account",
                label: "Early Repayment Fee Income Account",
                default: "",
                help: "Ledger account ID for early repayment fee income",
                param_type: "text",
                options: "",
            },
        ],
    },
    ProductTypeInfo {
        id: "home_loan_redraw",
        name: "Home Loan Redraw",
        description: "Variable-rate home loan with redraw facility",
        tside: "ASSET",
        denominations: &["CAD", "AUD"],
        default_modules: &["deposit-interest-accrual", "deposit-interest-application"],
        default_params: &[
            ProductParamDefault {
                key: "variable_interest_rate",
                label: "Variable Interest Rate",
                default: "0.0649",
                help: "Annual variable interest rate",
                param_type: "percentage",
                options: "",
            },
            ProductParamDefault {
                key: "loan_term_months",
                label: "Loan Term (months)",
                default: "360",
                help: "Total loan term",
                param_type: "integer",
                options: "",
            },
            ProductParamDefault {
                key: "due_amount_calculation_day",
                label: "Due Amount Calculation Day",
                default: "1",
                help: "Day of month (1-28)",
                param_type: "integer",
                options: "",
            },
            ProductParamDefault {
                key: "redraw_enabled",
                label: "Redraw Enabled",
                default: "true",
                help: "Whether redraw facility is enabled",
                param_type: "boolean",
                options: "",
            },
            ProductParamDefault {
                key: "redraw_fee",
                label: "Redraw Fee",
                default: "0",
                help: "Fee per redraw transaction",
                param_type: "decimal",
                options: "",
            },
            ProductParamDefault {
                key: "amortisation_method",
                label: "Amortisation Method",
                default: "straight_line",
                help: "Amortisation method",
                param_type: "select",
                options: "straight_line,reducing_balance",
            },
            ProductParamDefault {
                key: "interest_received_account",
                label: "Interest Received Account",
                default: "",
                help: "Ledger account ID for interest received (income)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "accrued_interest_receivable_account",
                label: "Accrued Interest Receivable Account",
                default: "",
                help: "Ledger account ID for accrued interest receivable",
                param_type: "text",
                options: "",
            },
        ],
    },
    ProductTypeInfo {
        id: "line_of_credit",
        name: "Line of Credit",
        description: "Pre-agreed credit line with multiple drawdown loans",
        tside: "ASSET",
        denominations: &["CAD", "USD", "EUR"],
        default_modules: &[
            "deposit-interest-accrual",
            "deposit-interest-application",
            "deposit-limits",
            "withdrawal-limits",
        ],
        default_params: &[
            ProductParamDefault {
                key: "credit_limit",
                label: "Credit Limit",
                default: "50000",
                help: "Maximum credit line",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "variable_interest_rate",
                label: "Variable Interest Rate",
                default: "0.0799",
                help: "Annual interest rate",
                param_type: "percentage",
                options: "",
            },
            ProductParamDefault {
                key: "interest_accrual_rest_type",
                label: "Interest Accrual Rest Type",
                default: "daily",
                help: "How interest is accrued",
                param_type: "select",
                options: "daily,continuous",
            },
            ProductParamDefault {
                key: "minimum_repayment",
                label: "Minimum Repayment",
                default: "100",
                help: "Minimum monthly repayment",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "interest_received_account",
                label: "Interest Received Account",
                default: "",
                help: "Ledger account ID for interest received (income)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "accrued_interest_receivable_account",
                label: "Accrued Interest Receivable Account",
                default: "",
                help: "Ledger account ID for accrued interest receivable",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "late_repayment_fee_income_account",
                label: "Late Fee Income Account",
                default: "",
                help: "Ledger account ID for late repayment fee income",
                param_type: "text",
                options: "",
            },
        ],
    },
    ProductTypeInfo {
        id: "bnpl_loan",
        name: "BNPL Loan",
        description: "Short-term interest-free instalment loan for point of sale",
        tside: "ASSET",
        denominations: &["CAD", "USD", "EUR", "GBP"],
        default_modules: &[],
        default_params: &[
            ProductParamDefault {
                key: "instalment_count",
                label: "Instalment Count",
                default: "4",
                help: "Number of instalments (typically 4)",
                param_type: "integer",
                options: "",
            },
            ProductParamDefault {
                key: "instalment_interval_days",
                label: "Instalment Interval (days)",
                default: "14",
                help: "Days between instalments",
                param_type: "integer",
                options: "",
            },
            ProductParamDefault {
                key: "interest_free_period_days",
                label: "Interest-Free Period (days)",
                default: "42",
                help: "Interest-free period",
                param_type: "integer",
                options: "",
            },
            ProductParamDefault {
                key: "late_fee",
                label: "Late Fee",
                default: "10",
                help: "Fee for late instalment",
                param_type: "decimal",
                options: "",
            },
            ProductParamDefault {
                key: "minimum_purchase_amount",
                label: "Minimum Purchase Amount",
                default: "50",
                help: "Minimum purchase amount for BNPL",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "late_repayment_fee_income_account",
                label: "Late Fee Income Account",
                default: "",
                help: "Ledger account ID for late repayment fee income",
                param_type: "text",
                options: "",
            },
        ],
    },
    ProductTypeInfo {
        id: "time_deposit",
        name: "Time Deposit",
        description: "Term deposit with maturity date and locked-in period",
        tside: "LIABILITY",
        denominations: &["CAD", "USD", "EUR", "GBP"],
        default_modules: &[
            "denomination-validation",
            "deposit-limits",
            "maximum-balance",
            "deposit-interest-accrual",
            "deposit-interest-application",
        ],
        default_params: &[
            ProductParamDefault {
                key: "interest_rate",
                label: "Interest Rate",
                default: "0.035",
                help: "Annual interest rate",
                param_type: "percentage",
                options: "",
            },
            ProductParamDefault {
                key: "term_months",
                label: "Term (months)",
                default: "12",
                help: "Deposit term in months (> 0)",
                param_type: "integer",
                options: "",
            },
            ProductParamDefault {
                key: "minimum_deposit",
                label: "Minimum Deposit",
                default: "1000",
                help: "Minimum deposit amount",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "maximum_balance",
                label: "Maximum Balance",
                default: "1000000",
                help: "Maximum deposit amount",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "early_withdrawal_penalty_rate",
                label: "Early Withdrawal Penalty Rate",
                default: "0.01",
                help: "Penalty rate for early withdrawal",
                param_type: "percentage",
                options: "",
            },
            ProductParamDefault {
                key: "interest_paid_account",
                label: "Interest Paid Account",
                default: "",
                help: "Ledger account ID for interest paid (debit side)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "interest_received_account",
                label: "Interest Received Account",
                default: "",
                help: "Ledger account ID for interest received (income)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "accrued_interest_payable_account",
                label: "Accrued Interest Payable Account",
                default: "",
                help: "Ledger account ID for accrued interest payable",
                param_type: "text",
                options: "",
            },
        ],
    },
    ProductTypeInfo {
        id: "wallet",
        name: "Wallet",
        description: "Multi-currency wallet with auto top-up and spending limits",
        tside: "LIABILITY",
        denominations: &["CAD", "USD", "EUR", "GBP", "SGD", "AED"],
        default_modules: &[
            "denomination-validation",
            "deposit-limits",
            "withdrawal-limits",
            "maximum-balance",
        ],
        default_params: &[
            ProductParamDefault {
                key: "maximum_balance",
                label: "Maximum Balance",
                default: "50000",
                help: "Maximum wallet balance",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "daily_spending_limit",
                label: "Daily Spending Limit",
                default: "5000",
                help: "Maximum daily spending",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "auto_topup_enabled",
                label: "Auto Top-up Enabled",
                default: "false",
                help: "Whether auto top-up is enabled",
                param_type: "boolean",
                options: "",
            },
            ProductParamDefault {
                key: "auto_topup_threshold",
                label: "Auto Top-up Threshold",
                default: "100",
                help: "Balance threshold for auto top-up",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "auto_topup_amount",
                label: "Auto Top-up Amount",
                default: "500",
                help: "Amount for auto top-up",
                param_type: "number",
                options: "",
            },
        ],
    },
    ProductTypeInfo {
        id: "us_checking",
        name: "US Checking",
        description: "US-style checking with overdraft protection via linked savings",
        tside: "LIABILITY",
        denominations: &["CAD", "USD"],
        default_modules: &[
            "denomination-validation",
            "deposit-limits",
            "withdrawal-limits",
            "maximum-balance",
            "deposit-interest-accrual",
            "deposit-interest-application",
            "minimum-balance-fee",
            "maintenance-fees",
            "inactivity-fee",
            "dormancy",
        ],
        default_params: &[
            ProductParamDefault {
                key: "interest_rate",
                label: "Interest Rate",
                default: "0.0005",
                help: "Annual interest rate",
                param_type: "percentage",
                options: "",
            },
            ProductParamDefault {
                key: "overdraft_limit",
                label: "Overdraft Limit",
                default: "250",
                help: "Overdraft limit",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "monthly_maintenance_fee",
                label: "Monthly Maintenance Fee",
                default: "10.00",
                help: "Monthly fee",
                param_type: "decimal",
                options: "",
            },
            ProductParamDefault {
                key: "minimum_balance",
                label: "Minimum Balance",
                default: "500",
                help: "Minimum balance to avoid fees",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "overdraft_protection_enabled",
                label: "Overdraft Protection Enabled",
                default: "true",
                help: "Whether overdraft protection via linked savings is enabled",
                param_type: "boolean",
                options: "",
            },
            ProductParamDefault {
                key: "interest_paid_account",
                label: "Interest Paid Account",
                default: "",
                help: "Ledger account ID for interest paid (debit side)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "interest_received_account",
                label: "Interest Received Account",
                default: "",
                help: "Ledger account ID for interest received (income)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "monthly_maintenance_fee_income_account",
                label: "Monthly Fee Income Account",
                default: "",
                help: "Ledger account ID for monthly maintenance fee income",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "inactivity_fee_income_account",
                label: "Inactivity Fee Income Account",
                default: "",
                help: "Ledger account ID for inactivity fee income",
                param_type: "text",
                options: "",
            },
        ],
    },
    ProductTypeInfo {
        id: "us_savings",
        name: "US Savings",
        description: "US-style savings account, linked to US Checking for overdraft",
        tside: "LIABILITY",
        denominations: &["CAD", "USD"],
        default_modules: &[
            "denomination-validation",
            "deposit-limits",
            "withdrawal-limits",
            "maximum-balance",
            "deposit-interest-accrual",
            "deposit-interest-application",
            "minimum-balance-fee",
            "maintenance-fees",
            "inactivity-fee",
            "dormancy",
        ],
        default_params: &[
            ProductParamDefault {
                key: "interest_rate",
                label: "Interest Rate",
                default: "0.015",
                help: "Annual interest rate",
                param_type: "percentage",
                options: "",
            },
            ProductParamDefault {
                key: "minimum_balance",
                label: "Minimum Balance",
                default: "200",
                help: "Minimum balance to avoid fees",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "maximum_balance",
                label: "Maximum Balance",
                default: "250000",
                help: "Maximum balance",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "monthly_maintenance_fee",
                label: "Monthly Maintenance Fee",
                default: "5.00",
                help: "Monthly fee",
                param_type: "decimal",
                options: "",
            },
            ProductParamDefault {
                key: "interest_application_frequency",
                label: "Interest Application Frequency",
                default: "monthly",
                help: "How often interest is applied",
                param_type: "select",
                options: "daily,monthly,quarterly,annually",
            },
            ProductParamDefault {
                key: "interest_paid_account",
                label: "Interest Paid Account",
                default: "",
                help: "Ledger account ID for interest paid (debit side)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "interest_received_account",
                label: "Interest Received Account",
                default: "",
                help: "Ledger account ID for interest received (income)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "monthly_maintenance_fee_income_account",
                label: "Monthly Fee Income Account",
                default: "",
                help: "Ledger account ID for monthly maintenance fee income",
                param_type: "text",
                options: "",
            },
        ],
    },
    ProductTypeInfo {
        id: "shariah_savings_account",
        name: "Shariah Savings",
        description: "Shariah-compliant deposit account with profit rates (MYR)",
        tside: "LIABILITY",
        denominations: &["CAD", "MYR"],
        default_modules: &[
            "denomination-validation",
            "deposit-limits",
            "withdrawal-limits",
            "maximum-balance",
            "deposit-interest-accrual",
            "deposit-interest-application",
        ],
        default_params: &[
            ProductParamDefault {
                key: "profit_rate",
                label: "Profit Rate",
                default: "0.025",
                help: "Annual profit rate (Shariah-compliant)",
                param_type: "percentage",
                options: "",
            },
            ProductParamDefault {
                key: "minimum_balance",
                label: "Minimum Balance",
                default: "500",
                help: "Minimum balance",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "maximum_balance",
                label: "Maximum Balance",
                default: "1000000",
                help: "Maximum balance",
                param_type: "number",
                options: "",
            },
            ProductParamDefault {
                key: "interest_application_frequency",
                label: "Profit Application Frequency",
                default: "monthly",
                help: "How often profit is applied",
                param_type: "select",
                options: "daily,monthly,quarterly,annually",
            },
            ProductParamDefault {
                key: "profit_paid_account",
                label: "Profit Paid Account",
                default: "",
                help: "Ledger account ID for profit paid (debit side)",
                param_type: "text",
                options: "",
            },
            ProductParamDefault {
                key: "accrued_profit_payable_account",
                label: "Accrued Profit Payable Account",
                default: "",
                help: "Ledger account ID for accrued profit payable",
                param_type: "text",
                options: "",
            },
        ],
    },
];

fn all_module_options() -> Vec<FormFieldOption> {
    vec![
        FormFieldOption {
            value: "denomination-validation".into(),
            label: "Denomination Validation".into(),
        },
        FormFieldOption {
            value: "deposit-limits".into(),
            label: "Deposit Limits".into(),
        },
        FormFieldOption {
            value: "withdrawal-limits".into(),
            label: "Withdrawal Limits".into(),
        },
        FormFieldOption {
            value: "transaction-type-limits".into(),
            label: "Transaction Type Limits".into(),
        },
        FormFieldOption {
            value: "maximum-balance".into(),
            label: "Maximum Balance".into(),
        },
        FormFieldOption {
            value: "deposit-interest-accrual".into(),
            label: "Deposit Interest Accrual".into(),
        },
        FormFieldOption {
            value: "deposit-interest-application".into(),
            label: "Deposit Interest Application".into(),
        },
        FormFieldOption {
            value: "minimum-balance-fee".into(),
            label: "Minimum Balance Fee".into(),
        },
        FormFieldOption {
            value: "maintenance-fees".into(),
            label: "Maintenance Fees".into(),
        },
        FormFieldOption {
            value: "inactivity-fee".into(),
            label: "Inactivity Fee".into(),
        },
        FormFieldOption {
            value: "overdraft-protection".into(),
            label: "Overdraft Protection".into(),
        },
        FormFieldOption {
            value: "overdraft-protection-sweep".into(),
            label: "Overdraft Protection Sweep".into(),
        },
        FormFieldOption {
            value: "closure-interest-application".into(),
            label: "Closure Interest Application".into(),
        },
        FormFieldOption {
            value: "dormancy".into(),
            label: "Dormancy".into(),
        },
    ]
}

/// Stage 1: Product type selection - card grid of 13 product types.
/// Each card is a Button that navigates to products/new?type={id}.
fn product_type_selection_page() -> AdminUiPage {
    // Card-based layout: each product type is a clickable button that
    // navigates to the config form. The button label includes the product
    // name, description, tside, and currencies so the user sees a summary
    // before clicking.
    let cards: Vec<RemoteWidget> = PRODUCT_TYPES
        .iter()
        .map(|pt| {
            RemoteWidget::Button(WidgetButton {
                label: format!(
                    "{}\n{} ({})\nCurrencies: {} · {} modules",
                    pt.name,
                    pt.description,
                    pt.tside,
                    pt.denominations.join(", "),
                    pt.default_modules.len()
                ),
                button_type: ButtonType::Link,
                route: Some(format!("products/new?type={}", pt.id)),
                endpoint: None,
                icon: Some(product_type_icon(pt.id).to_string()),
            })
        })
        .collect();

    AdminPage::new("Select Product Type")
        .widget(RemoteWidget::Container(WidgetContainer {
            direction: ContainerDirection::Vertical,
            spacing: 12.0,
            padding: 16.0,
            children: cards,
        }))
        .build()
}

/// Map product type IDs to Material Icons code points (hex strings).
fn product_type_icon(id: &str) -> &'static str {
    match id {
        "current_account" => "e850",  // account_balance_wallet
        "savings_account" => "e2bd",  // savings
        "credit_card" => "e070",      // credit_card
        "loan" => "e8ab",             // request_quote
        "mortgage" => "e318",         // home
        "home_loan_redraw" => "e318", // home
        "line_of_credit" => "e59d",   // credit_score
        "bnpl_loan" => "e54f",        // shopping_bag
        "time_deposit" => "e422",     // hourglass_top
        "wallet" => "e8f1",           // account_balance
        "us_checking" => "e850",      // account_balance_wallet
        "us_savings" => "e2bd",       // savings
        "shariah_savings" => "e90c",  // mosque
        _ => "e8b6",                  // account_circle
    }
}

/// Stage 2: Type-specific basic config form.
/// Shows name, denomination (type-specific), modules (pre-selected defaults).
async fn product_create_config_page(
    pool: &sqlx::PgPool,
    headers: &axum::http::HeaderMap,
    token_env: uuid::Uuid,
    type_id: &str,
) -> AdminUiPage {
    let pt = PRODUCT_TYPES
        .iter()
        .find(|t| t.id == type_id)
        .unwrap_or(&PRODUCT_TYPES[0]);

    let denom_options: Vec<FormFieldOption> = pt
        .denominations
        .iter()
        .map(|d| FormFieldOption {
            value: d.to_string(),
            label: d.to_string(),
        })
        .collect();

    let default_modules: serde_json::Value = serde_json::Value::Array(
        pt.default_modules
            .iter()
            .map(|m| serde_json::Value::String(m.to_string()))
            .collect(),
    );

    // Resolve env from TLS headers (X-Sentin8-Env-Id) so we query
    // internal accounts for the correct tenant, not the token's system env.
    let env_id = crate::handlers::resolve_org_env(headers, uuid::Uuid::nil(), token_env);

    // Fetch internal accounts for this env so we can populate
    // account-selection dropdowns with real seeded accounts.
    let default_denom = pt.denominations[0];
    let internal_accounts = fetch_internal_accounts(pool, env_id, default_denom).await;

    AdminPage::new(format!("Create {} ({})", pt.name, pt.tside))
        .widget(RemoteWidget::Form(WidgetForm {
            fields: vec![
                WidgetFormField {
                    key: "name".into(),
                    label: "Product Name".into(),
                    field_type: FormFieldType::Text,
                    required: true,
                    placeholder: Some(format!("e.g. iBank {}", pt.name)),
                    default_value: None,
                    options: None,
                    validation: Some(FormFieldValidation {
                        min: None, max: None, pattern: None,
                        min_length: Some(1), max_length: Some(100),
                        custom_message: Some("Product name is required".into()),
                    }),
                    width: None, help_text: None, visible_if: None,
                },
                WidgetFormField {
                    key: "product_type".into(),
                    label: "Product Type".into(),
                    field_type: FormFieldType::Hidden,
                    required: true,
                    placeholder: None,
                    default_value: Some(serde_json::Value::String(type_id.into())),
                    options: None,
                    validation: None,
                    width: None, help_text: None, visible_if: None,
                },
                WidgetFormField {
                    key: "denomination".into(),
                    label: "Denomination".into(),
                    field_type: FormFieldType::Select,
                    required: true,
                    placeholder: None,
                    default_value: Some(serde_json::Value::String(pt.denominations[0].into())),
                    options: Some(denom_options),
                    validation: None,
                    width: None,
                    help_text: Some("The primary currency for this product.".into()),
                    visible_if: None,
                },
                WidgetFormField {
                    key: "modules".into(),
                    label: "Contract Modules".into(),
                    field_type: FormFieldType::Multiselect,
                    required: false,
                    placeholder: None,
                    default_value: Some(default_modules),
                    options: Some(all_module_options()),
                    validation: None,
                    width: None,
                    help_text: Some("Modules control features like interest, fees, limits, and overdraft. Defaults are pre-selected based on the product type.".into()),
                    visible_if: None,
                },
            ]
            .into_iter()
            .chain(pt.default_params.iter().map(|p| {
                // Internal account params (key ends with "_account") are
                // rendered as a Select dropdown populated from ALL seeded
                // internal accounts for this org/env/denomination. The
                // default is the best-matching account - the param key
                // minus "_account" is matched against the account's
                // product_type (e.g. "interest_paid_account" → "interest_paid").
                if p.key.ends_with("_account") {
                    let account_type = p.key.trim_end_matches("_account");
                    // Show ALL internal accounts in the dropdown.
                    let options: Vec<FormFieldOption> = internal_accounts
                        .iter()
                        .map(|(_pt, id, nick)| FormFieldOption {
                            value: id.clone(),
                            label: nick.clone(),
                        })
                        .collect();
                    // Default: best match by product_type. Exact match first,
                    // then suffix match (e.g. "monthly_maintenance_fee_income"
                    // matches "maintenance_fee_income" by suffix).
                    let default_val = internal_accounts
                        .iter()
                        .find(|(pt, _, _)| pt == account_type)
                        .or_else(|| internal_accounts.iter().find(|(pt, _, _)| pt.ends_with(account_type) || account_type.ends_with(pt)))
                        .map(|(_, id, _)| id.clone())
                        .unwrap_or_default();
                    return WidgetFormField {
                        key: format!("param_{}", p.key),
                        label: p.label.into(),
                        field_type: FormFieldType::Select,
                        required: false,
                        placeholder: Some("Select account".into()),
                        default_value: Some(serde_json::Value::String(default_val)),
                        options: if options.is_empty() { None } else { Some(options) },
                        validation: None,
                        width: None,
                        help_text: Some(p.help.into()),
                        visible_if: None,
                    };
                }
                let field_type = match p.param_type {
                    "number" => FormFieldType::Number,
                    "decimal" => FormFieldType::Decimal,
                    "percentage" => FormFieldType::Decimal,
                    "integer" => FormFieldType::Number,
                    "select" => FormFieldType::Select,
                    "boolean" => FormFieldType::Toggle,
                    _ => FormFieldType::Text,
                };
                let options: Option<Vec<FormFieldOption>> = if p.options.is_empty() {
                    None
                } else {
                    Some(p.options.split(',').map(|o| FormFieldOption {
                        value: o.trim().to_string(),
                        label: o.trim().to_string(),
                    }).collect())
                };
                let validation: Option<FormFieldValidation> = match p.param_type {
                    "number" | "decimal" | "percentage" => Some(FormFieldValidation {
                        min: Some(0.0), max: None, pattern: None,
                        min_length: None, max_length: None,
                        custom_message: Some("Must be a positive number".into()),
                    }),
                    "integer" => Some(FormFieldValidation {
                        min: Some(0.0), max: None, pattern: Some(r"^\d+$".into()),
                        min_length: None, max_length: None,
                        custom_message: Some("Must be a positive integer".into()),
                    }),
                    _ => None,
                };
                WidgetFormField {
                    key: format!("param_{}", p.key),
                    label: p.label.into(),
                    field_type,
                    required: false,
                    placeholder: Some(p.default.into()),
                    default_value: Some(serde_json::Value::String(p.default.into())),
                    options,
                    validation,
                    width: None,
                    help_text: Some(p.help.into()),
                    visible_if: None,
                }
            }))
            .collect(),
            submit_endpoint: "/v1/admin/products".into(),
            submit_label: "Create Product".into(),
            cancel_label: "Cancel".into(),
            method: FormMethod::Post,
        }))
        .build()
}

/// Product detail page - shows product info + actions (Edit, Versions, Activate).
fn product_detail_page(id: &str) -> AdminUiPage {
    AdminPage::new("Product Detail")
        .action(AdminUiAction {
            label: "Edit".into(),
            action_type: AdminUiActionType::Link,
            route: Some(format!("products/{id}/edit")),
            endpoint: None,
            icon: Some("0xe3c9".into()),
        })
        .action(AdminUiAction {
            label: "New Version".into(),
            action_type: AdminUiActionType::Link,
            route: Some(format!("products/{id}/versions/new")),
            endpoint: None,
            icon: Some("0xe145".into()),
        })
        .action(AdminUiAction {
            label: "Activate".into(),
            action_type: AdminUiActionType::Link,
            route: Some(format!("products/{id}/activate")),
            endpoint: None,
            icon: Some("0xe876".into()),
        })
        // Product info table - fetches the single product by ID.
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Name".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "product_type".into(),
                    label: "Type".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "version".into(),
                    label: "Version".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "modules".into(),
                    label: "Modules".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "parameters".into(),
                    label: "Parameters".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: format!("/products/{id}"),
            sortable: false,
            filterable: false,
            page_size: 1,
            empty_message: Some("Product not found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        // Versions table - shows all versions for this product.
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "version_number".into(),
                    label: "Version".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "tside".into(),
                    label: "T-Side".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "supported_denominations".into(),
                    label: "Denominations".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "created_at".into(),
                    label: "Created".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
            ],
            data_endpoint: format!("/products/{id}/versions"),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No versions yet.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

/// Product edit page - edit name, modules, parameters.
fn product_edit_page(id: &str) -> AdminUiPage {
    AdminPage::new("Edit Product")
        .widget(RemoteWidget::Form(WidgetForm {
            fields: vec![
                WidgetFormField {
                    key: "name".into(),
                    label: "Product Name".into(),
                    field_type: FormFieldType::Text,
                    required: true,
                    placeholder: None,
                    default_value: None,
                    options: None,
                    validation: Some(FormFieldValidation {
                        min: None,
                        max: None,
                        pattern: None,
                        min_length: Some(1),
                        max_length: Some(100),
                        custom_message: Some("Product name is required".into()),
                    }),
                    width: None,
                    help_text: None,
                    visible_if: None,
                },
                WidgetFormField {
                    key: "modules".into(),
                    label: "Contract Modules".into(),
                    field_type: FormFieldType::Multiselect,
                    required: false,
                    placeholder: None,
                    default_value: None,
                    options: Some(vec![
                        FormFieldOption {
                            value: "denomination-validation".into(),
                            label: "Denomination Validation".into(),
                        },
                        FormFieldOption {
                            value: "deposit-limits".into(),
                            label: "Deposit Limits".into(),
                        },
                        FormFieldOption {
                            value: "withdrawal-limits".into(),
                            label: "Withdrawal Limits".into(),
                        },
                        FormFieldOption {
                            value: "transaction-type-limits".into(),
                            label: "Transaction Type Limits".into(),
                        },
                        FormFieldOption {
                            value: "maximum-balance".into(),
                            label: "Maximum Balance".into(),
                        },
                        FormFieldOption {
                            value: "deposit-interest-accrual".into(),
                            label: "Deposit Interest Accrual".into(),
                        },
                        FormFieldOption {
                            value: "deposit-interest-application".into(),
                            label: "Deposit Interest Application".into(),
                        },
                        FormFieldOption {
                            value: "minimum-balance-fee".into(),
                            label: "Minimum Balance Fee".into(),
                        },
                        FormFieldOption {
                            value: "maintenance-fees".into(),
                            label: "Maintenance Fees".into(),
                        },
                        FormFieldOption {
                            value: "inactivity-fee".into(),
                            label: "Inactivity Fee".into(),
                        },
                        FormFieldOption {
                            value: "overdraft-protection".into(),
                            label: "Overdraft Protection".into(),
                        },
                        FormFieldOption {
                            value: "overdraft-protection-sweep".into(),
                            label: "Overdraft Protection Sweep".into(),
                        },
                        FormFieldOption {
                            value: "closure-interest-application".into(),
                            label: "Closure Interest Application".into(),
                        },
                        FormFieldOption {
                            value: "dormancy".into(),
                            label: "Dormancy".into(),
                        },
                    ]),
                    validation: None,
                    width: None,
                    help_text: Some("Enable/disable contract modules for this product.".into()),
                    visible_if: None,
                },
                WidgetFormField {
                    key: "parameters".into(),
                    label: "Product Parameters".into(),
                    field_type: FormFieldType::KeyValue,
                    required: false,
                    placeholder: None,
                    default_value: None,
                    options: None,
                    validation: None,
                    width: None,
                    help_text: Some("Add/update product parameters as key-value pairs.".into()),
                    visible_if: None,
                },
            ],
            submit_endpoint: format!("/v1/admin/products/{id}"),
            submit_label: "Save Changes".into(),
            cancel_label: "Cancel".into(),
            method: FormMethod::Put,
        }))
        .build()
}

/// Product versions list page.
fn product_versions_page(id: &str) -> AdminUiPage {
    AdminPage::new("Product Versions")
        .action(AdminUiAction {
            label: "New Version".into(),
            action_type: AdminUiActionType::Link,
            route: Some(format!("products/{id}/versions/new")),
            endpoint: None,
            icon: Some("0xe145".into()),
        })
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "version_number".into(),
                    label: "Version".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "tside".into(),
                    label: "T-Side".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "supported_denominations".into(),
                    label: "Denominations".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "contract_modules".into(),
                    label: "Contract Modules".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "created_at".into(),
                    label: "Created".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
            ],
            data_endpoint: format!("/products/{id}/versions"),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No versions yet.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

/// Product version create page - form for creating a new version.
fn product_version_create_page(id: &str) -> AdminUiPage {
    AdminPage::new("New Product Version")
        .widget(RemoteWidget::Form(WidgetForm {
            fields: vec![
                WidgetFormField {
                    key: "tside".into(),
                    label: "T-Side (Accounting Side)".into(),
                    field_type: FormFieldType::Select,
                    required: true,
                    placeholder: None,
                    default_value: Some(serde_json::Value::String("LIABILITY".into())),
                    options: Some(vec![
                        FormFieldOption { value: "LIABILITY".into(), label: "Liability (deposits, savings)".into() },
                        FormFieldOption { value: "ASSET".into(), label: "Asset (loans, credit cards)".into() },
                        FormFieldOption { value: "UNKNOWN".into(), label: "Unknown".into() },
                    ]),
                    validation: None,
                    width: None,
                    help_text: Some("Determines whether the account is a liability (bank owes customer) or asset (customer owes bank).".into()),
                    visible_if: None,
                },
                WidgetFormField {
                    key: "supported_denominations".into(),
                    label: "Supported Denominations".into(),
                    field_type: FormFieldType::Text,
                    required: false,
                    placeholder: Some("USD, EUR, GBP".into()),
                    default_value: Some(serde_json::Value::String("USD".into())),
                    options: None,
                    validation: None,
                    width: None,
                    help_text: Some("Comma-separated list of supported currency denominations.".into()),
                    visible_if: None,
                },
                WidgetFormField {
                    key: "contract_modules".into(),
                    label: "Contract Modules (JSON)".into(),
                    field_type: FormFieldType::Textarea,
                    required: false,
                    placeholder: Some(r#"["deposit-interest-accrual","maintenance-fees"]"#.into()),
                    default_value: Some(serde_json::Value::String("[]".into())),
                    options: None,
                    validation: None,
                    width: None,
                    help_text: Some("JSON array of contract module names to enable for this version.".into()),
                    visible_if: None,
                },
                WidgetFormField {
                    key: "parameters".into(),
                    label: "Version Parameters".into(),
                    field_type: FormFieldType::KeyValue,
                    required: false,
                    placeholder: None,
                    default_value: None,
                    options: None,
                    validation: None,
                    width: None,
                    help_text: Some("Version-specific parameters as key-value pairs. These override the product-level parameters.".into()),
                    visible_if: None,
                },
                WidgetFormField {
                    key: "expected_parameters".into(),
                    label: "Expected Parameters".into(),
                    field_type: FormFieldType::Multiselect,
                    required: false,
                    placeholder: None,
                    default_value: None,
                    options: Some(vec![
                        FormFieldOption { value: "interest_rate".into(), label: "Interest Rate".into() },
                        FormFieldOption { value: "min_balance".into(), label: "Minimum Balance".into() },
                        FormFieldOption { value: "fee_amount".into(), label: "Fee Amount".into() },
                        FormFieldOption { value: "credit_limit".into(), label: "Credit Limit".into() },
                        FormFieldOption { value: "term_months".into(), label: "Term (months)".into() },
                        FormFieldOption { value: "accrual_frequency".into(), label: "Accrual Frequency".into() },
                        FormFieldOption { value: "payment_frequency".into(), label: "Payment Frequency".into() },
                        FormFieldOption { value: "overdraft_limit".into(), label: "Overdraft Limit".into() },
                    ]),
                    validation: None,
                    width: None,
                    help_text: Some("Parameters that must be provided when opening an account with this version.".into()),
                    visible_if: None,
                },
            ],
            submit_endpoint: format!("/v1/admin/products/{id}/versions"),
            submit_label: "Create Version".into(),
            cancel_label: "Cancel".into(),
            method: FormMethod::Post,
        }))
        .build()
}

/// Parameter create page.
fn parameter_create_page() -> AdminUiPage {
    AdminPage::new("Create Parameter")
        .widget(RemoteWidget::Form(WidgetForm {
            fields: vec![
                WidgetFormField {
                    key: "name".into(),
                    label: "Parameter Name".into(),
                    field_type: FormFieldType::Text,
                    required: true,
                    placeholder: Some("e.g. interest_rate".into()),
                    default_value: None,
                    options: None,
                    validation: Some(FormFieldValidation {
                        min: None,
                        max: None,
                        pattern: None,
                        min_length: Some(1),
                        max_length: Some(100),
                        custom_message: Some("Parameter name is required".into()),
                    }),
                    width: None,
                    help_text: None,
                    visible_if: None,
                },
                WidgetFormField {
                    key: "description".into(),
                    label: "Description".into(),
                    field_type: FormFieldType::Text,
                    required: false,
                    placeholder: Some("What this parameter controls".into()),
                    default_value: None,
                    options: None,
                    validation: None,
                    width: None,
                    help_text: None,
                    visible_if: None,
                },
                WidgetFormField {
                    key: "data_type".into(),
                    label: "Data Type".into(),
                    field_type: FormFieldType::Select,
                    required: true,
                    placeholder: None,
                    default_value: Some(serde_json::Value::String("string".into())),
                    options: Some(vec![
                        FormFieldOption {
                            value: "string".into(),
                            label: "String".into(),
                        },
                        FormFieldOption {
                            value: "number".into(),
                            label: "Number".into(),
                        },
                        FormFieldOption {
                            value: "boolean".into(),
                            label: "Boolean".into(),
                        },
                        FormFieldOption {
                            value: "json".into(),
                            label: "JSON Object".into(),
                        },
                    ]),
                    validation: None,
                    width: None,
                    help_text: None,
                    visible_if: None,
                },
                WidgetFormField {
                    key: "is_template".into(),
                    label: "Template Parameter".into(),
                    field_type: FormFieldType::Toggle,
                    required: false,
                    placeholder: None,
                    default_value: Some(serde_json::Value::Bool(true)),
                    options: None,
                    validation: None,
                    width: None,
                    help_text: Some(
                        "Template parameters are shared across all accounts of a product.".into(),
                    ),
                    visible_if: None,
                },
                WidgetFormField {
                    key: "is_instance".into(),
                    label: "Instance Parameter".into(),
                    field_type: FormFieldType::Toggle,
                    required: false,
                    placeholder: None,
                    default_value: Some(serde_json::Value::Bool(false)),
                    options: None,
                    validation: None,
                    width: None,
                    help_text: Some("Instance parameters are unique per account.".into()),
                    visible_if: None,
                },
                WidgetFormField {
                    key: "is_derived".into(),
                    label: "Derived Parameter".into(),
                    field_type: FormFieldType::Toggle,
                    required: false,
                    placeholder: None,
                    default_value: Some(serde_json::Value::Bool(false)),
                    options: None,
                    validation: None,
                    width: None,
                    help_text: Some("Derived parameters are computed at runtime.".into()),
                    visible_if: None,
                },
                WidgetFormField {
                    key: "constraints".into(),
                    label: "Constraints (JSON)".into(),
                    field_type: FormFieldType::Textarea,
                    required: false,
                    placeholder: Some(r#"{"min": 0, "max": 1}"#.into()),
                    default_value: Some(serde_json::Value::String("{}".into())),
                    options: None,
                    validation: None,
                    width: None,
                    help_text: Some("Type/range constraints as JSON.".into()),
                    visible_if: None,
                },
            ],
            submit_endpoint: "/v1/admin/parameters".into(),
            submit_label: "Create Parameter".into(),
            cancel_label: "Cancel".into(),
            method: FormMethod::Post,
        }))
        .build()
}

/// Restriction create page.
fn restriction_create_page() -> AdminUiPage {
    AdminPage::new("Create Restriction Set")
        .widget(RemoteWidget::Form(WidgetForm {
            fields: vec![
                WidgetFormField {
                    key: "restriction_definition_id".into(),
                    label: "Restriction Definition".into(),
                    field_type: FormFieldType::Select,
                    required: true,
                    placeholder: None,
                    default_value: None,
                    options: None, // populated dynamically from /restriction-definitions
                    validation: None,
                    width: None,
                    help_text: None,
                    visible_if: None,
                },
                WidgetFormField {
                    key: "account_id".into(),
                    label: "Account ID".into(),
                    field_type: FormFieldType::Text,
                    required: false,
                    placeholder: Some("UUID of the account".into()),
                    default_value: None,
                    options: None,
                    validation: None,
                    width: None,
                    help_text: Some("Provide either an Account ID or Customer ID.".into()),
                    visible_if: None,
                },
                WidgetFormField {
                    key: "customer_id".into(),
                    label: "Customer ID".into(),
                    field_type: FormFieldType::Text,
                    required: false,
                    placeholder: Some("UUID of the customer".into()),
                    default_value: None,
                    options: None,
                    validation: None,
                    width: None,
                    help_text: None,
                    visible_if: None,
                },
                WidgetFormField {
                    key: "expiry_timestamp".into(),
                    label: "Expiry (optional)".into(),
                    field_type: FormFieldType::DateTime,
                    required: false,
                    placeholder: None,
                    default_value: None,
                    options: None,
                    validation: None,
                    width: None,
                    help_text: Some("When the restriction should expire.".into()),
                    visible_if: None,
                },
            ],
            submit_endpoint: "/v1/admin/restriction-sets".into(),
            submit_label: "Create Restriction".into(),
            cancel_label: "Cancel".into(),
            method: FormMethod::Post,
        }))
        .build()
}

/// Flag create page.
fn flag_create_page() -> AdminUiPage {
    AdminPage::new("Create Flag")
        .widget(RemoteWidget::Form(WidgetForm {
            fields: vec![
                WidgetFormField {
                    key: "flag_definition_id".into(),
                    label: "Flag Definition".into(),
                    field_type: FormFieldType::Select,
                    required: true,
                    placeholder: None,
                    default_value: None,
                    options: None, // populated dynamically from /flag-definitions
                    validation: None,
                    width: None,
                    help_text: None,
                    visible_if: None,
                },
                WidgetFormField {
                    key: "account_id".into(),
                    label: "Account ID".into(),
                    field_type: FormFieldType::Text,
                    required: false,
                    placeholder: Some("UUID of the account".into()),
                    default_value: None,
                    options: None,
                    validation: None,
                    width: None,
                    help_text: Some("Provide either an Account ID or Customer ID.".into()),
                    visible_if: None,
                },
                WidgetFormField {
                    key: "customer_id".into(),
                    label: "Customer ID".into(),
                    field_type: FormFieldType::Text,
                    required: false,
                    placeholder: Some("UUID of the customer".into()),
                    default_value: None,
                    options: None,
                    validation: None,
                    width: None,
                    help_text: None,
                    visible_if: None,
                },
                WidgetFormField {
                    key: "value".into(),
                    label: "Flag Value".into(),
                    field_type: FormFieldType::Select,
                    required: true,
                    placeholder: None,
                    default_value: Some(serde_json::Value::String("ON".into())),
                    options: Some(vec![
                        FormFieldOption {
                            value: "ON".into(),
                            label: "ON".into(),
                        },
                        FormFieldOption {
                            value: "OFF".into(),
                            label: "OFF".into(),
                        },
                    ]),
                    validation: None,
                    width: None,
                    help_text: None,
                    visible_if: None,
                },
            ],
            submit_endpoint: "/v1/admin/flags".into(),
            submit_label: "Create Flag".into(),
            cancel_label: "Cancel".into(),
            method: FormMethod::Post,
        }))
        .build()
}

fn schedules_page() -> AdminUiPage {
    AdminPage::new("Schedules")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Schedule ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Name".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "type".into(),
                    label: "Type".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "last_run_at".into(),
                    label: "Last Run".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
            ],
            data_endpoint: "/schedules".into(),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No schedules found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

/// The jobs page (LED-JB1) - job history per schedule with the
/// `overridden` status surfaced: a batch-republished failed job renders
/// as overridden (a deliberate human close-out), not as an error. The
/// status filter lets operators isolate failed/overridden job sets.
fn jobs_page() -> AdminUiPage {
    AdminPage::new("Jobs")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Job ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "schedule_id".into(),
                    label: "Schedule".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "job_type".into(),
                    label: "Type".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: Some("badge".into()),
                },
                WidgetDataTableColumn {
                    key: "started_at".into(),
                    label: "Started".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
                WidgetDataTableColumn {
                    key: "completed_at".into(),
                    label: "Completed".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
                WidgetDataTableColumn {
                    key: "error_message".into(),
                    label: "Error".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/jobs".into(),
            sortable: true,
            filterable: true,
            page_size: 20,
            empty_message: Some("No jobs found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn dlq_page() -> AdminUiPage {
    AdminPage::new("Dead-Letter Queue")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Entry ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "error_type".into(),
                    label: "Error Type".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "retry_count".into(),
                    label: "Retries".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "created_at".into(),
                    label: "Created".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
            ],
            data_endpoint: "/dlq".into(),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No DLQ entries.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn reconcile_page() -> AdminUiPage {
    AdminPage::new("Reconciliation")
        .widget(RemoteWidget::Text(WidgetText {
            text: "Reconciliation dashboard - match/mismatch summary.".into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        }))
        .build()
}

fn balances_page() -> AdminUiPage {
    AdminPage::new("Balances")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "account_id".into(),
                    label: "Account ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "account_name".into(),
                    label: "Account".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "committed".into(),
                    label: "Committed".into(),
                    sortable: true,
                    width: None,
                    format: Some("currency".into()),
                },
                WidgetDataTableColumn {
                    key: "pending".into(),
                    label: "Pending".into(),
                    sortable: true,
                    width: None,
                    format: Some("currency".into()),
                },
                WidgetDataTableColumn {
                    key: "available".into(),
                    label: "Available".into(),
                    sortable: true,
                    width: None,
                    format: Some("currency".into()),
                },
            ],
            data_endpoint: "/balances".into(),
            sortable: true,
            filterable: true,
            page_size: 20,
            empty_message: Some("No balances found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn parameters_page() -> AdminUiPage {
    AdminPage::new("Parameters")
        .action(AdminUiAction {
            label: "Create Parameter".into(),
            action_type: AdminUiActionType::Link,
            route: Some("parameters/new".into()),
            endpoint: None,
            icon: Some("0xe145".into()),
        })
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Name".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "description".into(),
                    label: "Description".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "data_type".into(),
                    label: "Data Type".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "is_template".into(),
                    label: "Template".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "is_instance".into(),
                    label: "Instance".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "is_derived".into(),
                    label: "Derived".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/parameters".into(),
            sortable: true,
            filterable: true,
            page_size: 20,
            empty_message: Some("No parameters found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn restrictions_page() -> AdminUiPage {
    AdminPage::new("Restrictions")
        .action(AdminUiAction {
            label: "Create Restriction".into(),
            action_type: AdminUiActionType::Link,
            route: Some("restrictions/new".into()),
            endpoint: None,
            icon: Some("0xe145".into()),
        })
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "restriction_definition_id".into(),
                    label: "Definition".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "account_id".into(),
                    label: "Account".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "customer_id".into(),
                    label: "Customer".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "effective_timestamp".into(),
                    label: "Effective".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
                WidgetDataTableColumn {
                    key: "expiry_timestamp".into(),
                    label: "Expiry".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
            ],
            data_endpoint: "/restriction-sets".into(),
            sortable: true,
            filterable: true,
            page_size: 20,
            empty_message: Some("No restriction sets found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn flags_page() -> AdminUiPage {
    AdminPage::new("Flags")
        .action(AdminUiAction {
            label: "Create Flag".into(),
            action_type: AdminUiActionType::Link,
            route: Some("flags/new".into()),
            endpoint: None,
            icon: Some("0xe145".into()),
        })
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "flag_definition_id".into(),
                    label: "Definition".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "account_id".into(),
                    label: "Account".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "customer_id".into(),
                    label: "Customer".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "value".into(),
                    label: "Value".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "effective_timestamp".into(),
                    label: "Effective".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
            ],
            data_endpoint: "/flags".into(),
            sortable: true,
            filterable: true,
            page_size: 20,
            empty_message: Some("No flags found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn customers_page() -> AdminUiPage {
    AdminPage::new("Customers")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Customer ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "display_name".into(),
                    label: "Name".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "email".into(),
                    label: "Email".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/customers".into(),
            sortable: true,
            filterable: true,
            page_size: 20,
            empty_message: Some("No customers found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn statements_page() -> AdminUiPage {
    AdminPage::new("Statements")
        .widget(RemoteWidget::Text(WidgetText {
            text: "Statement management - list and download account statements.".into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        }))
        .build()
}

fn settings_page() -> AdminUiPage {
    AdminPage::new("Ledger Settings")
        .widget(RemoteWidget::Text(WidgetText {
            text: "Bank8:Ledger configuration settings.".into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        }))
        .build()
}

/// Fetch internal accounts for the given org/env/denomination.
/// Returns a list of (product_type, account_id, nickname) tuples that
/// `product_create_config_page` uses to populate account-selection dropdowns.
async fn fetch_internal_accounts(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    denom: &str,
) -> Vec<(String, String, String)> {
    let rows = sqlx::query(
        r#"SELECT product_type, id::text, nickname FROM accounts
           WHERE env_id = $1
             AND account_type = 'internal'
             AND denomination = $2
           ORDER BY product_type, nickname"#,
    )
    .bind(env_id)
    .bind(denom)
    .fetch_all(pool)
    .await;

    match rows {
        Ok(r) => r
            .into_iter()
            .map(|row| {
                let pt: String = row.get("product_type");
                let id: String = row.get("id");
                let nick: String = row.get("nickname");
                (pt, id, nick)
            })
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "admin_ui: failed to fetch internal accounts for product form");
            vec![]
        }
    }
}
