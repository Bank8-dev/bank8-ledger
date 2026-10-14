// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Customer handlers — customers CRUD.

use axum::{extract::{Path, State}, http::{HeaderMap, StatusCode}, Json};
use serde::Deserialize;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{err_db, set_tenant_context, set_tenant_context_ext, AppState};

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct CustomerResponse {
    pub id: Uuid,
    pub display_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub status: String,
    pub sentin8_auth_user_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Resolved display name: uses customers.display_name if non-empty,
    /// otherwise falls back to the linked auth user's first_name + last_name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_display_name: Option<String>,
    /// Resolved email: uses customers.email if non-null, otherwise
    /// falls back to the linked auth user's email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_email: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCustomerRequest {
    pub display_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
}

/// Query params for `GET /v1/customers` (list/search).
#[derive(Debug, Deserialize, ToSchema)]
pub struct ListCustomersQuery {
    /// Free-text search: matches display_name or email (case-insensitive).
    #[serde(default)]
    pub search: Option<String>,
    /// Target env_id for the query. Staff tokens carry
    /// env_id = System Env; the caller passes the real env_id here so
    /// the query scopes to the correct environment. Ignored for
    /// holder tokens (they are already env-scoped).
    #[serde(default)]
    pub env_id: Option<String>,
}

/// `POST /v1/customers` — create a customer.
/// If the caller is a user token, the `sentin8_auth_user_id` is stamped
/// from their token claims so that holder-scoped RLS and
/// `resolve_caller_customer_id` can find the row.
#[utoipa::path(
    post,
    path = "/v1/customers",
    request_body = CreateCustomerRequest,
    responses(
        (status = 200, description = "Customer created", body = CustomerResponse),
        (status = 409, description = "Customer already exists"),
        (status = 403, description = "Missing bank8:ledger:customers:write scope"),
    ),
    security(("bank8:ledger:customers:write" = [])),
    tag = "ledger",
)]
pub async fn create_customer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCustomerRequest>,
) -> Result<Json<CustomerResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:accounts:write")).await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, a.env_id(), &a).await.map_err(err_db)?;
    // Stamp `sentin8_auth_user_id` for every USER token (the §4.3c holder
    // link). This used to be gated on the dead `subject_type ==
    // "customer"` check — user access tokens never return "customer", so
    // the column stayed NULL and holder-scoped RLS had nothing to match.
    // M2M tokens (staff tooling / service provisioning) have no user id →
    // NULL, which is correct for staff-created customer records.
    let sentin8_auth_user_id = a.claims.sentin8_auth_user_uuid();
    let row = sqlx::query(
        r#"INSERT INTO customers (env_id, display_name, email, phone, sentin8_auth_user_id)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, display_name, email, phone, status, sentin8_auth_user_id, created_at"#,
    )
    .bind(a.env_id()).bind(&req.display_name).bind(req.email.as_deref()).bind(req.phone.as_deref())
    .bind(sentin8_auth_user_id)
    .fetch_one(&mut *conn).await;
    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            return Err((StatusCode::CONFLICT, "customer already exists".into()));
        }
        Err(e) => return Err(err_db(e)),
    };
    let customer = row_to_customer(&row);
    super::emit_event(&state.pool, a.env_id(), "bank8:ledger:customer:created",
        serde_json::json!({ "customer_id": customer.id, "display_name": req.display_name }),
    ).await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(customer))
}

/// `GET /v1/customers` — list/search customers.
/// Optional `?search=<text>` filters by display_name or email (case-insensitive
/// substring match). Without a search term, returns all customers in the
/// caller's org/env (subject to RLS).
#[utoipa::path(
    get,
    path = "/v1/customers",
    params(
        ("search" = Option<String>, Query, description = "Free-text search (display_name or email)"),
        ("env_id" = Option<String>, Query, description = "Target env_id for staff callers"),
    ),
    responses(
        (status = 200, description = "List of customers", body = [CustomerResponse]),
        (status = 403, description = "Missing bank8:ledger:accounts:read scope"),
    ),
    security(("bank8:ledger:accounts:read" = [])),
    tag = "ledger",
)]
pub async fn list_customers(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ListCustomersQuery>,
) -> Result<Json<Vec<CustomerResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read")).await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    // Resolve the effective env_id (isolation-design §10 — staff-realm
    // directory reads).
    // After Option A (§8) `holder:view-all` is M2M-only, so `is_holder `
    // can no longer classify callers: every staff token "lacks the scope"
    // yet is not a customer holder. Classification instead keys on WHAT the
    // token identifies:
    // - Customer-realm tokens (customer sign-in, CIBA-delegated with
    // `sub`=customer, M2M) stay env-locked to their claims `env_id`. A
    // foreign-env request is rejected, never widened.
    // - Staff-realm tokens (user tokens that identify a sentin8:Auth user
    // able to hold org roles/groups) may pass the ?env_id= override so
    // the customer DIRECTORY is searchable before any CIBA delegation
    // exists (§4.3f requires the customer id to start the flow). The
    // override is validated against the REQUESTED env's org — the caller
    // must hold a role or group in that org — and platform admins bypass
    // the check. Staff groups (e.g. app:e_teller) live in the org's
    // staff-auth env, so membership resolves through
    // auth_groups/auth_roles.env_id → sys_environments.org_id.
    // The SQL query's `WHERE env_id = $N` clause remains the primary data
    // scoping; RLS is the backstop.
    let staff_realm = a.claims.sentin8_auth_user_uuid().is_some();
    let effective_env_id = if let Some(ref s) = q.env_id.as_deref().filter(|s| !s.is_empty()) {
        let requested = uuid::Uuid::parse_str(s)
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid env_id format".into()))?;
        if requested == a.env_id() || a.is_platform_admin() {
            // Own env (no widening) or platform admin.
            requested
        } else if staff_realm {
            // Validate: the caller must have a role or group whose env
            // belongs to the org of the REQUESTED env.
            // VDC §VDC.5 — the org relationship is resolved through
            // Sys's tenant-snapshot API (the sanctioned on-demand
            // cross-tenant read); the former cross-database
            // `sentin8.auth_*`/`sentin8.sys_*` joins never existed in
            // the vertical's own database and failed every request.
            let caller_org = crate::tenant_snapshot::env_org_id(a.env_id())
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("org check: {e}")))?;
            let requested_org = crate::tenant_snapshot::env_org_id(requested)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("org check: {e}")))?;
            let has_org_access = matches!(
                (caller_org, requested_org),
                (Some(c), Some(r)) if c == r
            );
            if !has_org_access {
                return Err((StatusCode::FORBIDDEN, "not authorized for this organization".into()));
            }
            if !has_org_access {
                return Err((StatusCode::FORBIDDEN, "not authorized for this organization".into()));
            }
            requested
        } else {
            // Customer-realm caller requesting a foreign env — fail closed.
            return Err((StatusCode::FORBIDDEN, "cross-environment access is not permitted".into()));
        }
    } else {
        a.env_id()
    };
        // Scope by env_id — these explicit WHERE clauses are the primary
    // scoping; RLS is the backstop.
    // Local-only search (VDC §VDC.2): the ledger matches its OWN columns.
    // The former `sentin8.auth_users` enrichment join never existed in the
    // vertical's database — display_name/email are stamped on the customer
    // row at provisioning time (eBank sign-up proxies the customer create),
    // and the eTeller search matches on those.
    // Same-transaction context for the data SELECT (rule 2): the org
    // check above ran under no tenant context (its tables are remote),
    // so the context must be set HERE — before the customer query — on
    // the SAME transaction connection, or the RLS gate hides every row.
    set_tenant_context(&mut conn, effective_env_id).await.map_err(err_db)?;
    tracing::info!(env = %effective_env_id, search = ?q.search, caller_env = %a.env_id(), "bank8:ledger: list_customers query");
    let rows = if let Some(ref s) = q.search {
        let pattern = format!("%{}%", s.trim());
        sqlx::query(
            r#"SELECT c.id, c.display_name, c.email, c.phone, c.status,
                      c.sentin8_auth_user_id, c.created_at
                 FROM customers c
                WHERE c.customer_type = 'person'
                  AND (c.display_name ILIKE $1 OR c.email ILIKE $1)
                  AND c.env_id = $2
                ORDER BY c.created_at DESC"#,
        )
        .bind(&pattern).bind(effective_env_id)
        .fetch_all(&mut *conn).await.map_err(err_db)?
    } else {
        sqlx::query(
            r#"SELECT c.id, c.display_name, c.email, c.phone, c.status,
                      c.sentin8_auth_user_id, c.created_at
                 FROM customers c
                WHERE c.customer_type = 'person' AND c.env_id = $1
                ORDER BY c.created_at DESC"#,
        )
        .bind(effective_env_id)
        .fetch_all(&mut *conn).await.map_err(err_db)?
    };
    Ok(Json(rows.iter().map(row_to_customer).collect()))
}

/// `GET /v1/customers/{id}` — customer detail.
#[utoipa::path(
    get,
    path = "/v1/customers/{id}",
    params(("id" = Uuid, Path, description = "Customer ID")),
    responses(
        (status = 200, description = "Customer detail", body = CustomerResponse),
        (status = 404, description = "Customer not found"),
        (status = 403, description = "Missing bank8:ledger:accounts:read scope"),
    ),
    security(("bank8:ledger:accounts:read" = [])),
    tag = "ledger",
)]
pub async fn get_customer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<CustomerResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read")).await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    // Staff-realm directory read (isolation-design §10): resolve the row's
    // env, then authorize via org membership — a staff teller must be able
    // to open the detail of a customer found by search, without any CIBA
    // delegation (and without `holder:view-all`). Customer-realm callers
    // (no sentin8:Auth user id in `sub`) stay env-locked to their claims
    // env; cross-env requests 404 (never reveal existence cross-env).
    let caller_env = a.env_id();
    let staff_realm = a.claims.sentin8_auth_user_uuid().is_some();
    let row_env: Option<Uuid> = sqlx::query_scalar(
        "SELECT env_id FROM customers WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    let Some(row_env) = row_env else {
        return Err((StatusCode::NOT_FOUND, "customer not found".into()));
    };
    let effective_env_id = if row_env == caller_env || a.is_platform_admin() {
        row_env
    } else if staff_realm {
        // Cross-env staff read: org membership in the row's org is required.
        // VDC §VDC.5 — org relationship via Sys's tenant-snapshot API.
        let caller_org = crate::tenant_snapshot::env_org_id(caller_env)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("org check: {e}")))?;
        let row_org = crate::tenant_snapshot::env_org_id(row_env)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("org check: {e}")))?;
        let has_org_access = matches!(
            (caller_org, row_org),
            (Some(c), Some(r)) if c == r
        );
        if !has_org_access {
            return Err((StatusCode::NOT_FOUND, "customer not found".into()));
        }
        row_env
    } else {
        return Err((StatusCode::NOT_FOUND, "customer not found".into()));
    };
    set_tenant_context(&mut conn, effective_env_id).await.map_err(err_db)?;
    let row = sqlx::query(
        r#"SELECT c.id, c.display_name, c.email, c.phone, c.status,
                  c.sentin8_auth_user_id, c.created_at
             FROM customers c
            WHERE c.id = $1 AND c.env_id = $2"#,
    )
    .bind(id).bind(effective_env_id)
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    Ok(Json(row_to_customer(&row)))
}

fn row_to_customer(row: &sqlx::postgres::PgRow) -> CustomerResponse {
    let display_name: String = row.get("display_name");
    let email: Option<String> = row.get("email");

    // Resolve display_name: if the customer row has a non-empty display_name,
    // use it. Otherwise, fall back to the auth user's first_name + last_name.
    let sentin8_auth_first: Option<String> = row.try_get("sentin8_auth_first_name").ok().flatten();
    let sentin8_auth_last: Option<String> = row.try_get("sentin8_auth_last_name").ok().flatten();
    let sentin8_auth_email: Option<String> = row.try_get("sentin8_auth_email").ok().flatten();

    let resolved_display_name = if !display_name.is_empty() {
        None // display_name is already populated
    } else {
        let full = match (&sentin8_auth_first, &sentin8_auth_last) {
            (Some(f), Some(l)) => format!("{} {}", f, l),
            (Some(f), None) => f.clone(),
            (None, Some(l)) => l.clone(),
            (None, None) => String::new(),
        };
        if full.is_empty() { None } else { Some(full) }
    };

    let resolved_email = if email.as_deref().map(|e| !e.is_empty()).unwrap_or(false) {
        None // email is already populated (non-empty)
    } else {
        sentin8_auth_email.filter(|e| !e.is_empty())
    };

    CustomerResponse {
        id: row.get("id"),
        display_name,
        email,
        phone: row.get("phone"),
        status: row.get("status"),
        sentin8_auth_user_id: row.get("sentin8_auth_user_id"),
        created_at: row.get("created_at"),
        resolved_display_name,
        resolved_email,
    }
}

// ── .9: Auth user link ─────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct LinkAuthRequest {
    pub sentin8_auth_user_id: Uuid,
    /// Optional local display_name stamp (VDC §VDC.2 — the ledger never
    /// joins the platform auth schema; the caller supplies the identity
    /// fields it already verified).
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

#[utoipa::path(
    post,
    path = "/v1/customers/{id}/link-auth",
    params(("id" = Uuid, Path, description = "Customer ID")),
    request_body = LinkAuthRequest,
    responses(
        (status = 200, description = "Customer linked to auth user", body = CustomerResponse),
        (status = 409, description = "Auth user already linked to another customer"),
        (status = 403, description = "Missing bank8:ledger:customers:write scope"),
    ),
    security(("bank8:ledger:customers:write" = [])),
    tag = "ledger",
)]
pub async fn link_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<LinkAuthRequest>,
) -> Result<Json<CustomerResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:customers:write")).await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await.map_err(err_db)?;
    // Reject if the Auth user is already linked to a different customer.
    let existing: Option<(Uuid,)> = sqlx::query_as(
        r#"SELECT id FROM customers
            WHERE env_id = $1 AND sentin8_auth_user_id = $2 AND id <> $3"#,
    )
    .bind(a.env_id()).bind(req.sentin8_auth_user_id).bind(id)
    .fetch_optional(&mut *conn).await.map_err(err_db)?;
    if existing.is_some() {
        return Err((StatusCode::CONFLICT, "sentin8_auth_user_id already linked to another customer".into()));
    }
    let row = sqlx::query(
        r#"UPDATE customers c
              SET sentin8_auth_user_id = $2,
                  display_name = COALESCE(NULLIF($4, ''), c.display_name),
                  email = COALESCE(c.email, NULLIF($5, '')),
                  updated_at = now()
           WHERE c.id = $1 AND c.env_id = $3
           RETURNING c.id, c.display_name, c.email, c.phone, c.status,
                     c.sentin8_auth_user_id, c.created_at"#,
    )
    .bind(id).bind(req.sentin8_auth_user_id).bind(a.env_id())
    .bind(req.display_name.as_deref().unwrap_or(""))
    .bind(req.email.as_deref().unwrap_or(""))
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    let customer = row_to_customer(&row);
    super::emit_event(&state.pool, a.env_id(), "bank8:ledger:customer:authlinked",
        serde_json::json!({ "customer_id": id, "sentin8_auth_user_id": req.sentin8_auth_user_id }),
    ).await;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(customer))
}

// ── Customer update  ──────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCustomerRequest {
    #[serde(default)] pub display_name: Option<String>,
    #[serde(default)] pub email: Option<String>,
    #[serde(default)] pub phone: Option<String>,
}

/// `PUT /v1/customers/{id}/update` — update customer (display name / contact).
#[utoipa::path(
    put,
    path = "/v1/customers/{id}/update",
    params(("id" = Uuid, Path, description = "Customer ID")),
    request_body = UpdateCustomerRequest,
    responses(
        (status = 200, description = "Customer updated", body = CustomerResponse),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing bank8:ledger:customers:write scope"),
    ),
    security(("bank8:ledger:customers:write" = [])),
    tag = "ledger",
)]
pub async fn update_customer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCustomerRequest>,
) -> Result<Json<CustomerResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:customers:write")).await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, a.env_id(), &a).await.map_err(err_db)?;
    let row = sqlx::query(
        r#"UPDATE customers SET
               display_name = COALESCE($2, display_name),
               email = COALESCE($3, email),
               phone = COALESCE($4, phone),
               updated_at = now()
           WHERE id = $1 AND env_id = $5
           RETURNING id, display_name, email, phone, status, sentin8_auth_user_id, created_at"#,
    )
    .bind(id).bind(req.display_name.as_deref()).bind(req.email.as_deref())
    .bind(req.phone.as_deref()).bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, format!("customer {id} not found")))?;
    super::emit_event(&state.pool, a.env_id(), "bank8:ledger:customer:updated",
        serde_json::json!({ "customer_id": id, "fields_changed": ["profile"] }))
        .await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(row_to_customer(&row)))
}