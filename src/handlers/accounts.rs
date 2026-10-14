// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Account handlers — v1 (legacy), v2, balances v1/v2, transactions, statements.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use rust_decimal::Decimal;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{err_db, set_staff_override_context, set_tenant_context_ext, AppState};

/// Resolve the caller's `customers.id` for holder-scoped callers.
/// Returns `None` for staff/M2M tokens carrying `holder:view-all` (they see
/// all env accounts). Returns `Some(id)` for holders — used to force
/// `customer_id` in list queries (service-layer defence-in-depth for
/// holder-scoped RLS, §4.3c).
/// §4.3c primitive: a caller is a HOLDER iff the token lacks
/// `holder:view-all` (`auth.is_holder `). The old `subject_type ==
/// "customer"` check was dead code — `subject_type ` never returns
/// `"customer"` (incident 2026-08-28, RC2).
/// Returns `None` if no `customers` row exists — the caller will get
/// a 403 "no customers row" error from `create_account`, or an empty
/// list from the read handlers. The app is responsible for creating the
/// customer row via `POST /v1/customers` after sign-up (e.g. eBank does
/// this, eFintech does not).
async fn resolve_caller_customer_id(
    conn: &mut sqlx::PgConnection,
    auth: &auth::AuthContext,
) -> Option<Uuid> {
    if !auth.is_holder() {
        return None;
    }
    let user_id = auth.claims.sentin8_auth_user_uuid()?;

    sqlx::query_scalar("SELECT id FROM customers WHERE sentin8_auth_user_id = $1 LIMIT 1")
        .bind(user_id)
        .fetch_optional(conn)
        .await
        .ok()
        .flatten()
}

// ── v1 Account (legacy, kept for backwards compat) ──────────────────────

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct AccountResponse {
    pub id: Uuid,
    pub env_id: Uuid,
    pub customer_id: Option<Uuid>,
    pub product_id: Option<Uuid>,
    pub account_type: String,
    pub product_type: Option<String>,
    pub nickname: Option<String>,
    pub status: String,
    pub denomination: String,
    pub opened_at: chrono::DateTime<chrono::Utc>,
    pub closed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Current committed balance (joined from balances).
    /// Null if no balance row exists yet (new account with no postings).
    #[serde(skip_serializing_if = "Option::is_none", rename = "currentBalance")]
    pub current_balance: Option<Decimal>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAccountRequest {
    pub customer_id: Option<Uuid>,
    pub product_id: Option<Uuid>,
    pub account_type: String,
    pub product_type: Option<String>,
    pub nickname: Option<String>,
    #[serde(default = "default_denom")]
    pub denomination: String,
}

fn default_denom() -> String { "CAD".into() }

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAccountRequest {
    pub status: Option<String>,
    pub nickname: Option<String>,
}

/// `POST /v1/accounts` — create account (v1 legacy).
/// .5: holder callers can only create accounts owned by
/// themselves. Server-side defence-in-depth:
/// - If the caller is a holder (§4.3c — no `holder:view-all` scope) and
/// they did not supply `customer_id`, we resolve it from their Auth
/// user id (via `customers`).
/// - If the caller is a holder and they did supply a `customer_id` that
/// does not match their own, we return 403 (they cannot create
/// accounts for someone else).
/// - If no `customers` row exists for the holder, we return 403
/// — there is no way to own the account, so creating it would leave an
/// orphan (the list/get handlers then hide it forever).
/// - Callers with `holder:view-all` (staff / sys / M2M) are
/// unrestricted: they can pass any `customer_id` or none (for
/// internal accounts).
#[utoipa::path(
    post,
    path = "/v1/accounts",
    request_body = CreateAccountRequest,
    responses(
        (status = 200, description = "Account created", body = AccountResponse),
        (status = 400, description = "Invalid account type or module validation failed"),
        (status = 403, description = "Missing bank8:ledger:accounts:write scope"),
    ),
    security(("bank8:ledger:accounts:write" = [])),
    tag = "ledger",
)]
pub async fn create_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAccountRequest>,
) -> Result<Json<AccountResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:accounts:write")).await?;
    if !matches!(req.account_type.as_str(), "customer" | "internal") {
        return Err((StatusCode::BAD_REQUEST, "account_type must be customer|internal".into()));
    }
    let env_id = a.env_id();
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, env_id, &a).await.map_err(err_db)?;
    // DB constraint allows: active, closed, frozen. Customer accounts start
    // as "active" (the account is immediately usable). Internal accounts
    // also start as "active".
    let status = "active";

    // Resolve the effective customer_id from the caller's auth context.
    // Holder callers are forced to their own customer_id (and cannot
    // impersonate another customer). Callers with `holder:view-all`
    // (staff, sys, M2M) may pass any value, including None.
    let effective_customer_id: Option<Uuid> = if a.is_holder() {
        let own = resolve_caller_customer_id(&mut conn, &a).await;
        match (own, req.customer_id) {
            (None, _) => {
                return Err((
                    StatusCode::FORBIDDEN,
                    "no customers row linked to your auth user".into(),
                ));
            }
            (Some(own_id), Some(req_id)) if own_id != req_id => {
                return Err((
                    StatusCode::FORBIDDEN,
                    "customer_id does not match the caller".into(),
                ));
            }
            (Some(own_id), _) => Some(own_id),
        }
    } else {
        req.customer_id
    };

    // Module validation: if product_id is set, load the product's modules + parameters
    // and run validate_creation (denomination-validation, deposit-limits, etc.).
    if let Some(product_id) = req.product_id {
        let product_row = sqlx::query("SELECT product_type, parameters, modules FROM products WHERE id = $1 AND env_id = $2")
            .bind(product_id).bind(env_id).fetch_optional(&mut *conn).await.map_err(err_db)?;
        if let Some(row) = product_row {
            let product_type: Option<String> = row.get("product_type");
            let params: serde_json::Value = row.get("parameters");
            let modules_val: serde_json::Value = row.get("modules");
            let modules: Vec<String> = modules_val.as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let ctx = crate::modules::ModuleContext {
                product_parameters: &params,
                modules: &modules,
                instance_params: &serde_json::Value::Object(serde_json::Map::new()),
            };
            let account = crate::types::AccountV2 {
                id: uuid::Uuid::new_v4(),
                env_id,
                customer_id: effective_customer_id,
                product_id: Some(product_id),
                account_type: req.account_type.clone(),
                product_type: product_type.clone(),
                nickname: req.nickname.clone(),
                status: status.to_string(),
                denomination: req.denomination.clone(),
                permitted_denominations: vec![],
                tside: "LIABILITY".into(),
                processing_group_id: None,
                sentin8_func_version_id: None,
                pending_sentin8_func_version_id: None,
                stakeholder_ids: vec![],
                opened_at: Some(chrono::Utc::now()),
                closed_at: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            if let Err(e) = crate::modules::validate_creation(&ctx, &account, None) {
                tracing::warn!(error = %e, product_type = ?product_type, "account creation validation failed");
                return Err((StatusCode::BAD_REQUEST, e.to_string()));
            }
            if let Some(pt) = &product_type {
                if let Err(e) = crate::modules::validate_module_composition(pt, &modules) {
                    tracing::warn!(error = %e, product_type = %pt, "module composition validation failed");
                    return Err((StatusCode::BAD_REQUEST, e.to_string()));
                }
            }
        }
    }

    let row = sqlx::query(
        r#"INSERT INTO accounts (env_id, customer_id, product_id, account_type, product_type, nickname, denomination, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id, env_id, customer_id, product_id, account_type, product_type,
                     nickname, status, denomination, opened_at, closed_at, created_at,
                     NULL::numeric AS current_balance"#,
    )
    .bind(env_id).bind(effective_customer_id).bind(req.product_id)
    .bind(&req.account_type).bind(req.product_type.as_deref()).bind(req.nickname.as_deref())
    .bind(&req.denomination).bind(status)
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    let account = row_to_account(&row);
    // Story — emit account.created event to outbox.
    super::emit_event(
        &state.pool,
        env_id,
        "bank8:ledger:account:created",
        serde_json::json!({
            "account_id": account.id,
            "product_id": req.product_id,
            "customer_id": effective_customer_id,
        }),
    ).await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(account))
}

/// `GET /v1/accounts` — list accounts.
/// .5: holder callers (§4.3c — no `holder:view-all` scope) see only
/// accounts held by their own `customers` row, and only
/// `account_type='customer'` accounts (internal accounts are never exposed
/// to holders — forced here in the service layer; RLS is the backstop).
/// Callers with `holder:view-all` see all env accounts. A holder caller's
/// `?customer_id=` query param is ignored — they cannot impersonate another
/// customer.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ListAccountsQuery {
    #[serde(default)] pub customer_id: Option<Uuid>,
    #[serde(default)] pub product_id: Option<Uuid>,
    #[serde(default)] pub account_type: Option<String>,
    #[serde(default)] pub status: Option<String>,
    /// §10.1 — staff-realm env override for internal-account reads.
    /// Validated against org membership; ignored for customer/delegated
    /// tokens (env-locked) and never widens customer-data visibility.
    #[serde(default)] pub env_id: Option<String>,
}

#[utoipa::path(
    get,
    path = "/v1/accounts",
    params(
        ("customer_id" = Option<Uuid>, Query, description = "Filter by customer ID"),
        ("product_id" = Option<Uuid>, Query, description = "Filter by product ID"),
        ("account_type" = Option<String>, Query, description = "Filter by account type (customer|internal)"),
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("env_id" = Option<String>, Query, description = "Staff-realm env override for internal-account reads (org-validated)"),
    ),
    responses(
        (status = 200, description = "List of accounts", body = [AccountResponse]),
        (status = 403, description = "Missing bank8:ledger:accounts:read scope"),
    ),
    security(("bank8:ledger:accounts:read" = [])),
    tag = "ledger",
)]
pub async fn list_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListAccountsQuery>,
) -> Result<Json<Vec<AccountResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read")).await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    // §10.1 — staff-realm env override (isolation-design §10 pattern).
    // Internal accounts are counterparty plumbing seeded per CUSTOMER env,
    // while staff tokens claim the STAFF auth env — the resolver must be
    // able to read the org's prod env. The override is honored ONLY for
    // staff-realm callers (user token) whose membership in the requested
    // env's org is validated by the same SQL as `list_customers`, and ONLY
    // when the query is internal-account scoped — customer rows are never
    // exposed by this branch. Customer/delegated/M2M callers keep the
    // strict env-lock below.
    let mut staff_env_override: Option<Uuid> = None;
    if let Some(ref s) = q.env_id.as_deref().filter(|s| !s.is_empty()) {
        if a.claims.sentin8_auth_user_uuid().is_some() && !a.is_holder_view_all() {
            if let Ok(requested) = uuid::Uuid::parse_str(s) {
                if requested != a.env_id() && !a.is_platform_admin() {
 // VDC §VDC.5 — the org relationship is resolved through Sys's
 // tenant-snapshot API (the sanctioned on-demand cross-tenant
 // read); the former cross-database `sentin8.auth_*`/`sentin8.sys_*`
 // joins never existed in the vertical's own database and failed
 // every request with a 500 (same shape as `list_customers`).
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
                    if has_org_access {
                        staff_env_override = Some(requested);
                    }
                }
            }
        }
    }
    let effective_env = staff_env_override.unwrap_or_else(|| a.env_id());
    // Org-validated cross-env read → staff-override stamp (the RLS
    // policy admits stamped requests for this env only).
    if staff_env_override.is_some() {
        set_staff_override_context(&mut conn, effective_env, &a).await.map_err(err_db)?;
    } else {
        set_tenant_context_ext(&mut conn, effective_env, &a).await.map_err(err_db)?;
    }
    // Force customer_id for holder callers (defence-in-depth, §4.3c).
    // If the holder has no customers row, return an empty list
    // (NOT all accounts — the NULL customer_id would match every row).
    // Internal accounts (account_type='internal') are NEVER returned to
    // holders regardless of any query param — EXCEPT the §10.1 staff branch
    // above, which exists specifically for internal counterparty plumbing.
    // Callers with `holder:view-all` (M2M) may filter freely.
    let (effective_customer_id, effective_account_type) = if staff_env_override.is_some() {
        // Staff internal-account read: no customer filter, explicit
        // internal scoping only (request without account_type=internal is
        // rejected to keep this branch narrow).
        if q.account_type.as_deref() != Some("internal") {
            return Err((StatusCode::FORBIDDEN, "staff env override is only valid for account_type=internal".into()));
        }
        (None, Some("internal".to_string()))
    } else if a.is_holder() {
        let cid = resolve_caller_customer_id(&mut conn, &a).await;
        if cid.is_none() {
            return Ok(Json(Vec::new()));
        }
        (cid, Some("customer".to_string()))
    } else {
        (q.customer_id, q.account_type.clone())
    };
    let rows = sqlx::query(
        r#"SELECT a.id, a.env_id, a.customer_id, a.product_id, a.account_type, a.product_type,
                  a.nickname, a.status, a.denomination, a.opened_at, a.closed_at, a.created_at,
                  b.amount AS current_balance
             FROM accounts a
             LEFT JOIN balances b ON b.account_id = a.id AND b.phase = 'COMMITTED'
            WHERE a.deleted_at IS NULL
              AND a.env_id = $5
              AND ($1::uuid IS NULL OR a.customer_id = $1)
              AND ($2::uuid IS NULL OR a.product_id = $2)
              AND ($3::text IS NULL OR a.account_type = $3)
              AND ($4::text IS NULL OR a.status = $4)
            ORDER BY a.created_at DESC LIMIT 100"#,
    )
    .bind(effective_customer_id).bind(q.product_id).bind(effective_account_type.as_deref()).bind(q.status.as_deref())
    .bind(effective_env)
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    // §10.2 — resilient env-init seeding. The event-driven env-init
    // (seed_accounts via the Bus consumer) is the primary trigger, but the
    // SSE message can be lost on a mid-batch reconnect, leaving an enabled
    // env permanently unseeded — the teller's counterparty lookups would
    // stay empty forever. Self-heal: when the staff internal-account query
    // above returns empty, run the idempotent seed inline and re-query.
    let rows = if rows.is_empty()
        && staff_env_override.is_some()
        && q.account_type.as_deref() == Some("internal")
    {
        crate::handlers::seed_accounts::seed_internal_accounts(&state.pool, effective_env)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("internal-account seeding failed: {e}")))?;
        sqlx::query(
            r#"SELECT a.id, a.env_id, a.customer_id, a.product_id, a.account_type, a.product_type,
                      a.nickname, a.status, a.denomination, a.opened_at, a.closed_at, a.created_at,
                      b.amount AS current_balance
                 FROM accounts a
                 LEFT JOIN balances b ON b.account_id = a.id AND b.phase = 'COMMITTED'
                WHERE a.deleted_at IS NULL
                  AND a.env_id = $5
                  AND ($1::uuid IS NULL OR a.customer_id = $1)
                  AND ($2::uuid IS NULL OR a.product_id = $2)
                  AND ($3::text IS NULL OR a.account_type = $3)
                  AND ($4::text IS NULL OR a.status = $4)
                ORDER BY a.created_at DESC LIMIT 100"#,
        )
        .bind(effective_customer_id).bind(q.product_id).bind(effective_account_type.as_deref()).bind(q.status.as_deref())
        .bind(effective_env)
        .fetch_all(&mut *conn).await.map_err(err_db)?
    } else {
        rows
    };
    Ok(Json(rows.iter().map(row_to_account).collect()))
}

/// `GET /v1/accounts/{id}` — account detail.
/// .5: customer-realm callers can only fetch their own accounts
/// the service layer verifies the account's `customer_id` matches the
/// caller's customer before returning. RLS is the backstop.
#[utoipa::path(
    get,
    path = "/v1/accounts/{id}",
    params(("id" = Uuid, Path, description = "Account ID")),
    responses(
        (status = 200, description = "Account detail", body = AccountResponse),
        (status = 404, description = "Account not found"),
        (status = 403, description = "Missing bank8:ledger:accounts:read scope"),
    ),
    security(("bank8:ledger:accounts:read" = [])),
    tag = "ledger",
)]
pub async fn get_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<AccountResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read")).await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, a.env_id(), &a).await.map_err(err_db)?;
    // Defence-in-depth (AGENTS.md: explicit WHERE env_id is mandatory):
    // holders (§4.3c) can only fetch their own customer accounts.
    let row = if a.is_holder() {
        let caller_customer_id = resolve_caller_customer_id(&mut conn, &a).await;
        match caller_customer_id {
            None => return Err((StatusCode::NOT_FOUND, "account not found".into())),
            Some(cid) => {
                sqlx::query(
                    r#"SELECT id, env_id, customer_id, product_id, account_type, product_type,
                              nickname, status, denomination, opened_at, closed_at, created_at,
                              NULL::numeric AS current_balance
                         FROM accounts
                        WHERE id = $1 AND env_id = $2 AND customer_id = $3
                          AND account_type = 'customer' AND deleted_at IS NULL"#,
                )
                .bind(id).bind(a.env_id()).bind(cid)
                .fetch_optional(&mut *conn).await.map_err(err_db)?
                    .ok_or((StatusCode::NOT_FOUND, "account not found".into()))?
            }
        }
    } else {
        sqlx::query(
            r#"SELECT id, env_id, customer_id, product_id, account_type, product_type,
                      nickname, status, denomination, opened_at, closed_at, created_at,
                      NULL::numeric AS current_balance
                 FROM accounts WHERE id = $1 AND env_id = $2 AND deleted_at IS NULL"#,
        )
        .bind(id).bind(a.env_id())
        .fetch_optional(&mut *conn).await.map_err(err_db)?
            .ok_or((StatusCode::NOT_FOUND, "account not found".into()))?
    };
    Ok(Json(row_to_account(&row)))
}

/// `PUT /v1/accounts/{id}` — update account (status, nickname).
#[utoipa::path(
    put,
    path = "/v1/accounts/{id}",
    params(("id" = Uuid, Path, description = "Account ID")),
    request_body = UpdateAccountRequest,
    responses(
        (status = 200, description = "Account updated", body = AccountResponse),
        (status = 403, description = "Missing bank8:ledger:accounts:write scope"),
    ),
    security(("bank8:ledger:accounts:write" = [])),
    tag = "ledger",
)]
pub async fn update_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateAccountRequest>,
) -> Result<Json<AccountResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:accounts:write")).await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    // Extended setter (scopes + user id reach the RLS GUCs) — the legacy
    // 2-arg form left holder-scoped UPDATE policies untestable.
    set_tenant_context_ext(&mut conn, a.env_id(), &a).await.map_err(err_db)?;
    // Ownership check (§4.3c): holders may only update their own customer
    // accounts; `holder:view-all` callers may update any env account.
    if a.is_holder() {
        let caller_customer_id = resolve_caller_customer_id(&mut conn, &a).await;
        let owned: Option<Uuid> = match caller_customer_id {
            None => None,
            Some(cid) => sqlx::query_scalar(
                r#"SELECT id FROM accounts
                    WHERE id = $1 AND env_id = $2 AND customer_id = $3
                      AND account_type = 'customer' AND deleted_at IS NULL"#,
            )
            .bind(id).bind(a.env_id()).bind(cid)
            .fetch_optional(&mut *conn).await.map_err(err_db)?,
        };
        if owned.is_none() {
            return Err((StatusCode::NOT_FOUND, "account not found".into()));
        }
    }
    let row = sqlx::query(
        r#"UPDATE accounts
              SET nickname = COALESCE($2, nickname),
                  status = COALESCE($3, status),
                  closed_at = CASE WHEN $3 = 'CLOSED' THEN now() ELSE closed_at END,
                  updated_at = now()
            WHERE id = $1 AND env_id = $4 AND deleted_at IS NULL
            RETURNING id, env_id, customer_id, product_id, account_type, product_type,
                     nickname, status, denomination, opened_at, closed_at, created_at,
                     NULL::numeric AS current_balance"#,
    )
    .bind(id).bind(req.nickname.as_deref()).bind(req.status.as_deref())
    .bind(a.env_id())
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    let account = row_to_account(&row);
    // Story — emit account.updated event to outbox.
    let fields_changed: Vec<&str> = [
        req.nickname.as_deref().map(|_| "nickname"),
        req.status.as_deref().map(|_| "status"),
    ]
    .into_iter()
    .flatten()
    .collect();
    super::emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:account:updated",
        serde_json::json!({
            "account_id": id,
            "fields_changed": fields_changed,
        }),
    ).await;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(account))
}

// ── Balances ────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct BalanceResponse {
    pub account_id: Uuid,
    pub denomination: String,
    pub address: String,
    pub phase: String,
    pub amount: Decimal,
}

/// `GET /v1/accounts/{id}/balances` — live balances.
#[utoipa::path(
    get,
    path = "/v1/accounts/{id}/balances",
    params(("id" = Uuid, Path, description = "Account ID")),
    responses(
        (status = 200, description = "Account balances", body = [BalanceResponse]),
        (status = 403, description = "Missing bank8:ledger:balances:read scope"),
    ),
    security(("bank8:ledger:balances:read" = [])),
    tag = "ledger",
)]
pub async fn get_account_balances(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<BalanceResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:balances:read")).await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, a.env_id(), &a).await.map_err(err_db)?;
    // Defence-in-depth (§4.3c): holders can only see balances for their own
    // customer accounts. Verify ownership (scoped to the token env) before
    // returning balances.
    if a.is_holder() {
        let caller_customer_id = resolve_caller_customer_id(&mut conn, &a).await;
        let account_customer: Option<Uuid> = sqlx::query_scalar(
            "SELECT customer_id FROM accounts WHERE id = $1 AND env_id = $2 AND account_type = 'customer' AND deleted_at IS NULL",
        )
        .bind(id).bind(a.env_id())
        .fetch_optional(&mut *conn).await.map_err(err_db)?;
        if account_customer.is_none() || account_customer != caller_customer_id {
            return Ok(Json(Vec::new()));
        }
    }
    let rows = sqlx::query(
        r#"SELECT account_id, denomination, address, phase, amount
             FROM balances WHERE account_id = $1"#,
    )
    .bind(id).fetch_all(&mut *conn).await.map_err(err_db)?;
    let balances: Vec<BalanceResponse> = rows.iter().map(|r| BalanceResponse {
        account_id: r.get("account_id"),
        denomination: r.get("denomination"),
        address: r.get("address"),
        phase: r.get("phase"),
        amount: r.get("amount"),
    }).collect();
    Ok(Json(balances))
}

// ── Transactions ─────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct TransactionResponse {
    pub id: Uuid,
    pub account_id: Uuid,
    pub posting_id: Uuid,
    pub amount: Decimal,
    pub denomination: String,
    pub direction: String,
    pub description: Option<String>,
    pub value_timestamp: chrono::DateTime<chrono::Utc>,
    pub booking_timestamp: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/accounts/{id}/transactions` — transaction history.
#[utoipa::path(
    get,
    path = "/v1/accounts/{id}/transactions",
    params(
        ("id" = Uuid, Path, description = "Account ID"),
        ("from" = Option<chrono::DateTime<chrono::Utc>>, Query, description = "Filter from timestamp"),
        ("to" = Option<chrono::DateTime<chrono::Utc>>, Query, description = "Filter to timestamp"),
    ),
    responses(
        (status = 200, description = "Transaction history", body = [TransactionResponse]),
        (status = 403, description = "Missing bank8:ledger:accounts:read scope"),
    ),
    security(("bank8:ledger:accounts:read" = [])),
    tag = "ledger",
)]
pub async fn get_account_transactions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TransactionQuery>,
) -> Result<Json<Vec<TransactionResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read")).await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, a.env_id(), &a).await.map_err(err_db)?;
    // Defence-in-depth (§4.3c): holders can only see transactions for their
    // own customer accounts, scoped to the token env.
    if a.is_holder() {
        let caller_customer_id = resolve_caller_customer_id(&mut conn, &a).await;
        let account_customer: Option<Uuid> = sqlx::query_scalar(
            "SELECT customer_id FROM accounts WHERE id = $1 AND env_id = $2 AND account_type = 'customer' AND deleted_at IS NULL",
        )
        .bind(id).bind(a.env_id())
        .fetch_optional(&mut *conn).await.map_err(err_db)?;
        if account_customer.is_none() || account_customer != caller_customer_id {
            return Ok(Json(Vec::new()));
        }
    }
    let rows = sqlx::query(
        r#"SELECT id, account_id, posting_id, amount, denomination, direction, description,
                  value_timestamp, booking_timestamp
             FROM transactions
            WHERE account_id = $1
              AND ($2::timestamptz IS NULL OR value_timestamp >= $2)
              AND ($3::timestamptz IS NULL OR value_timestamp <= $3)
            ORDER BY value_timestamp DESC LIMIT 200"#,
    )
    .bind(id).bind(q.from).bind(q.to)
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    let txns: Vec<TransactionResponse> = rows.iter().map(|r| TransactionResponse {
        id: r.get("id"),
        account_id: r.get("account_id"),
        posting_id: r.get("posting_id"),
        amount: r.get("amount"),
        denomination: r.get("denomination"),
        direction: r.get("direction"),
        description: r.get("description"),
        value_timestamp: r.get("value_timestamp"),
        booking_timestamp: r.get("booking_timestamp"),
    }).collect();
    Ok(Json(txns))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TransactionQuery {
    #[serde(default)] pub from: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)] pub to: Option<chrono::DateTime<chrono::Utc>>,
}

// ── Statements ───────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct StatementResponse {
    pub id: Uuid,
    pub account_id: Uuid,
    pub period_start: chrono::DateTime<chrono::Utc>,
    pub period_end: chrono::DateTime<chrono::Utc>,
    pub opening_balance: Decimal,
    pub closing_balance: Decimal,
    pub document_url: Option<String>,
    pub document_format: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/accounts/{id}/statements` — list statements.
#[utoipa::path(
    get,
    path = "/v1/accounts/{id}/statements",
    params(("id" = Uuid, Path, description = "Account ID")),
    responses(
        (status = 200, description = "Account statements", body = [StatementResponse]),
        (status = 403, description = "Missing bank8:ledger:accounts:read scope"),
    ),
    security(("bank8:ledger:accounts:read" = [])),
    tag = "ledger",
)]
pub async fn get_account_statements(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<StatementResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read")).await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, a.env_id(), &a).await.map_err(err_db)?;
    // Defence-in-depth (§4.3c): holders can only see statements for their own
    // customer accounts, scoped to the token env.
    if a.is_holder() {
        let caller_customer_id = resolve_caller_customer_id(&mut conn, &a).await;
        let account_customer: Option<Uuid> = sqlx::query_scalar(
            "SELECT customer_id FROM accounts WHERE id = $1 AND env_id = $2 AND account_type = 'customer' AND deleted_at IS NULL",
        )
        .bind(id).bind(a.env_id())
        .fetch_optional(&mut *conn).await.map_err(err_db)?;
        if account_customer.is_none() || account_customer != caller_customer_id {
            return Ok(Json(Vec::new()));
        }
    }
    let rows = sqlx::query(
        r#"SELECT id, account_id, period_start, period_end, opening_balance, closing_balance,
                  document_url, document_format, created_at
             FROM statements WHERE account_id = $1 ORDER BY period_start DESC"#,
    )
    .bind(id).fetch_all(&mut *conn).await.map_err(err_db)?;
    let stmts: Vec<StatementResponse> = rows.iter().map(|r| StatementResponse {
        id: r.get("id"),
        account_id: r.get("account_id"),
        period_start: r.get("period_start"),
        period_end: r.get("period_end"),
        opening_balance: r.get("opening_balance"),
        closing_balance: r.get("closing_balance"),
        document_url: r.get("document_url"),
        document_format: r.get("document_format"),
        created_at: r.get("created_at"),
    }).collect();
    conn.commit().await.map_err(err_db)?;
    Ok(Json(stmts))
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn row_to_account(row: &sqlx::postgres::PgRow) -> AccountResponse {
    AccountResponse {
        id: row.get("id"),
        env_id: row.get("env_id"),
        customer_id: row.get("customer_id"),
        product_id: row.get("product_id"),
        account_type: row.get("account_type"),
        product_type: row.get("product_type"),
        nickname: row.get("nickname"),
        status: row.get("status"),
        denomination: row.get("denomination"),
        opened_at: row.get("opened_at"),
        closed_at: row.get("closed_at"),
        created_at: row.get("created_at"),
        current_balance: row.get("current_balance"),
    }
}