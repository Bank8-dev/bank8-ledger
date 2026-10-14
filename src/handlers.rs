// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Ledger HTTP handlers — re-exports from sub-modules.
//! The full Ledger API surface is split across sub-modules:
//! - `handlers_accounts` — accounts v1/v2, balances v1/v2, transactions, statements
//! - `handlers_postings` — posting instruction batches (sync/async), instructions, DLQ
//! - `handlers_products` — products, product versions, product activation
//! - `handlers_schedules` — schedules, jobs, calendars
//! - `handlers_flags` — flag definitions, flags
//! - `handlers_restrictions` — restriction definitions, restriction sets
//! - `handlers_params` — parameters, parameter values, hierarchy nodes
//! - `handlers_customers` — customers CRUD (incl. update)
//! - `handlers_audit` — audit events, action logs
//! Resource-family handler modules:
//! - `handlers_journal` — hash-chained journal events
//! - `handlers_adjustments` — adjustments + post-posting failures (/4)
//! - `handlers_balances_v2` — balances live/end/series
//! - `handlers_processing_groups` — EOD grouping config
//! - `handlers_calendar` — calendar events/periods/bookkeeping dates
//! - `handlers_schedule_tags` — schedule + account schedule tags
//! - `handlers_plans` — plans, migrations, account assocs
//! - `handlers_contracts` — contract catalog/simulate/supervisor
//! - `handlers_parameters_ext` — derived + global parameters
//! - `handlers_internal_accounts` — internal accounts
//! - `handlers_account_extras` — attributes + payment devices
//! - `handlers_bulk_batches` — migrations + update batches
//! - `handlers_streams` — streaming catalog
//! **Authorization model:** RBAC scopes are verified by
//! Sentin8:Auth; fine-grained attribute rules are **Shield** policies evaluated
//! upstream (Sentin8:Auth/Sentin8:BFF) — no handler evaluates policies locally
//! or queries role tables at request time (design §6.1). Staff access to
//! customer data arrives exclusively as **CIBA-delegated** customer tokens
//! with `act` claims (design §6.2); every tenant query sets the RLS context
//! on the same connection it reads.

pub mod accounts;
pub mod admin_ui;
pub mod audit;
pub mod customers;
pub mod event_consumer;
pub mod flags;
pub mod func_host;
pub mod params;
pub mod postings;
pub mod products;
pub mod restrictions;
pub mod schedules;
pub mod seed_accounts;
pub mod statement_regen;
// Business API completion handlers, one module per resource family.
pub mod account_extras;
pub mod adjustments;
pub mod balances_v2;
pub mod bulk_batches;
pub mod calendar;
pub mod contracts;
pub mod internal_accounts;
pub mod journal;
pub mod parameters_ext;
pub mod plans;
pub mod processing_groups;
pub mod schedule_tags;
pub mod streams;

use std::sync::Arc;

use crate::config::LedgerConfig;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<LedgerConfig>,
    pub pool: sqlx::PgPool,
    /// M2M-backed Bus client built at startup via DCR (RFC 7591).
    pub bus_client: sentin8::bus::client::BusClient,
    /// Shield policy engine : step 5 is the ONLY gate
    /// handlers verify the token (steps 1–4) then evaluate a
    /// `bank8:ledger:<resource>:<action>` target; no JWT scope check remains.
    pub policy: Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface (§3.6) — same engine
    /// instance the request path evaluates.
    pub admin: sentin8::shield::admin::SharedAdminState,
    /// Bounded TTL cache behind `parameter-values:viewEffective`
    /// (params DESIGN.md §10). The posting money path never consults it.
    pub effective_param_cache: Arc<params::EffectiveParamCache>,
}

/// Set the RLS tenant context on a connection.
/// MUST be called on the same connection that the subsequent data query uses,
/// because `sentin8_set_tenant_context` uses `set_config(..., true)` which is
/// transaction-local. The context vanishes when the transaction (or the
/// pooled connection's implicit transaction) ends.
/// Extended to pass the admin flags (option a) and the
/// Auth user UUID for holder-scoped RLS. Services that read customer-held
/// tables (`accounts`, `flags`, `restriction_sets`) must
/// use the extended form via [`set_tenant_context_ext`]; the legacy 2-arg
/// form is kept for tables that only need org/env scoping.
pub async fn set_tenant_context(
    conn: &mut sqlx::PgConnection,
    env_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, NULL, NULL, false, false, false, NULL, 'ledger')")
        .bind(env_id)
        .execute(conn)
        .await
        .map(|_| ())
}

/// Extended tenant context setter — resolves admin flags from the caller's
/// scopes (option a) and passes the Auth user UUID for holder-scoped RLS.
/// Use this for handlers that read `accounts`, `flags`, or
/// `restriction_sets` (the customer-held tables).
pub async fn set_tenant_context_ext(
    conn: &mut sqlx::PgConnection,
    env_id: uuid::Uuid,
    auth: &crate::auth::AuthContext,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT sentin8_set_tenant_context($1, $2, $3, $4, $5, false, $6, $7, 'ledger')")
        .bind(env_id)
        .bind(&auth.claims.sub)
        .bind(&auth.claims.token_tp)
        .bind(&auth.claims.scope)
        .bind(auth.is_platform_admin())
        .bind(auth.claims.is_env_admin())
        .bind(auth.claims.sentin8_auth_user_uuid())
        .execute(conn)
        .await
        .map(|_| ())
}

/// Staff-override context setter (isolation-design §10.1) — the handler has
/// ALREADY validated the caller's org relationship for a cross-env read
/// (via Sys's tenant-snapshot API); this stamps the request so the RLS
/// policies admit the counterparty-plumbing reads (internal accounts) in
/// the overridden env. Transaction-local — the stamp evaporates with the
/// transaction that carries the validated read.
pub async fn set_staff_override_context(
    conn: &mut sqlx::PgConnection,
    env_id: uuid::Uuid,
    auth: &crate::auth::AuthContext,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT sentin8_set_tenant_context($1, $2, $3, $4, $5, false, $6, $7, 'ledger', true)",
    )
    .bind(env_id)
    .bind(&auth.claims.sub)
    .bind(&auth.claims.token_tp)
    .bind(&auth.claims.scope)
    .bind(auth.is_platform_admin())
    .bind(auth.claims.is_env_admin())
    .bind(auth.claims.sentin8_auth_user_uuid())
    .execute(conn)
    .await
    .map(|_| ())
}

/// Resolve the effective env for a request.
/// Story — reads env from the token claims only. BFF exchanges
/// sys-realm tokens via RFC 8693 , so the JWT claims carry the
/// correct env. App BFF end-users already have env-scoped tokens from
/// Auth. No header overrides needed — the token is the single source of truth.
pub fn resolve_org_env(
    headers: &axum::http::HeaderMap,
    _token_org: uuid::Uuid,
    token_env: uuid::Uuid,
) -> uuid::Uuid {
    // Use the TLS-injected env header (X-Sentin8-Env-Id) when available
    // this is injected by the sentin8-tls context middleware based on the
    // request hostname. This allows the BFF to forward requests without
    // delegation: the session token carries the system env (for scope
    // checks), but the actual tenant context comes from the TLS headers.
    headers
        .get("x-sentin8-env-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .unwrap_or(token_env)
}

/// Standard DB error → HTTP 500.
pub fn err_db(e: sqlx::Error) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Emit a domain event to the service's LOCAL outbox (DBX producer path,
/// architecture-principles §6.7 — ledger design §11).
/// Inserts an `ledger.outbox` row that the shell's post-commit relay
/// drains to Bus `POST /v1/produce` (idempotency_key = row id). Call this
/// after the domain insert/update/delete succeeds — on handlers with an
/// open domain transaction, prefer `insert_outbox_row` on the SAME
/// transaction (outbox-first, atomic).
/// The outbox is FORCE-RLS'd; the pool helper sets the tenant context on
/// its own connection. Errors are logged and ignored — the outbox is
/// best-effort for non-posting entities (the posting path inserts
/// in-transaction with `?` propagation, §8.4 rule 2).
pub async fn emit_event(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    event_type: &str,
    payload: serde_json::Value,
) {
    if let Err(e) =
        sentin8::bus::outbox::insert_outbox_row_pool(pool, env_id, "ledger", event_type, &payload)
            .await
    {
        tracing::warn!(error = %e, event_type, "bank8:ledger: failed to emit outbox event");
    }
}

pub async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(
        serde_json::json!({ "status": "ok", "service": "ledger", "version": sentin8::build_info::id(), "build": sentin8::build_info::build_hash() }),
    )
}
