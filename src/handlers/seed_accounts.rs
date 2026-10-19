// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Seed internal bank accounts on the `sentin8:sys:service:updated` event.
//! Bank8:Ledger requires a set of internal accounts for each denomination
//! to serve as the counterparty for interest accrual, fee income, penalty
//! receivable, etc. These accounts are created idempotently when a service
//! of type `ledger` is enabled for an org/env.
//! Env-init is **event-driven**, not a synchronous RPC. Sentin8:Sys emits
//! `sentin8:sys:service:updated` to Sentin8:Bus (stream family `sys`) when
//! a service is enabled. The ledger's Bus consumer (see `event_consumer.rs`)
//! subscribes to that stream and calls `seed_internal_accounts ` when it
//! sees `service == "ledger"` and `enabled == true`. There is no
//! `POST /v1/internal/env-init` HTTP endpoint anymore.
//! F8 institution scout: internal accounts are owned by an explicit
//! `customer_type='institution'` party (the bank itself in this env) so
//! `accounts.customer_id` is never NULL.

use sqlx::PgPool;
use uuid::Uuid;

/// Standard internal account definitions per denomination.
/// Each product type references these account IDs in its parameters.
const SEED_ACCOUNTS: &[(&str, &str)] = &[
    // (nickname, product_type)
    ("Interest Paid", "interest_paid"),
    ("Interest Received", "interest_received"),
    ("Accrued Interest Payable", "accrued_interest_payable"),
    ("Accrued Interest Receivable", "accrued_interest_receivable"),
    ("Penalty Interest Received", "penalty_interest_received"),
    ("Late Repayment Fee Income", "late_repayment_fee_income"),
    ("Early Repayment Fee Income", "early_repayment_fee_income"),
    ("Upfront Fee Income", "upfront_fee_income"),
    ("Overpayment Fee Income", "overpayment_fee_income"),
    ("Maintenance Fee Income", "maintenance_fee_income"),
    ("Minimum Balance Fee Income", "minimum_balance_fee_income"),
    ("Inactivity Fee Income", "inactivity_fee_income"),
    ("Excess Fee Income", "excess_fee_income"),
    ("Overlimit Fee Income", "overlimit_fee_income"),
    ("Annual Fee Income", "annual_fee_income"),
    ("Paper Statement Fee Income", "paper_statement_fee_income"),
    ("Fee Rebate", "fee_rebate"),
    ("Deposit Account", "deposit"),
    // §3.1.3 (eteller design) - teller counterparty accounts. The resolver
    // in bank8/apps/eteller looks these nicknames up; they were never seeded
    // before, so teller postings failed with "internal account not found".
    ("ledger:cash_deposit_account", "cash_deposit"),
    ("ledger:cheque_clearing_account", "cheque_clearing"),
    ("ledger:liquidity_account", "liquidity"),
    ("ledger:clearing_account", "clearing"),
    ("ledger:suspense_account", "suspense"),
    (
        "Capitalised Interest Received",
        "capitalised_interest_received",
    ),
    (
        "Capitalised Interest Receivable",
        "capitalised_interest_receivable",
    ),
    (
        "Capitalised Penalties Received",
        "capitalised_penalties_received",
    ),
    ("Interest Write-off", "interest_write_off"),
    ("Principal Write-off", "principal_write_off"),
    ("Interest on Fees", "interest_on_fees"),
    ("Early Closure Fee Income", "early_closure_fee_income"),
    ("Payment Type Fee Income", "payment_type_fee_income"),
    (
        "Overdraft Interest Receivable",
        "overdraft_interest_receivable",
    ),
    ("Overdraft Interest Received", "overdraft_interest_received"),
    (
        "Unarranged Overdraft Fee Income",
        "unarranged_overdraft_fee_income",
    ),
    (
        "Unarranged Overdraft Fee Receivable",
        "unarranged_overdraft_fee_receivable",
    ),
    ("Profit Paid", "profit_paid"),
    ("Accrued Profit Payable", "accrued_profit_payable"),
    ("Line of Credit Account", "line_of_credit_account"),
    (
        "Overpayment Allowance Fee Income",
        "overpayment_allowance_fee_income",
    ),
];

/// Default denominations to seed accounts for.
const SEED_DENOMINATIONS: &[&str] = &["CAD", "USD", "EUR", "GBP", "AUD", "MYR", "SGD", "AED"];

/// Create-or-get the env's institution customer (F8 scout - the bank
/// itself as an explicit party).
/// Exactly one per env (enforced by the partial unique index on
/// `customer_type = 'institution'`). The row NEVER links an auth user
/// (`sentin8_auth_user_id` stays NULL) so the §4.3c holder subquery can
/// never match it - structurally invisible to customers.
async fn ensure_institution_customer(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
) -> anyhow::Result<Uuid> {
    let existing: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM ledger.customers
            WHERE env_id = $1 AND customer_type = 'institution'
            LIMIT 1"#,
    )
    .bind(env_id)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(id) = existing {
        return Ok(id);
    }
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO ledger.customers
               (env_id, customer_type, display_name, status, sentin8_auth_user_id)
           VALUES ($1, 'institution', 'Bank (internal accounts)', 'active', NULL)
           ON CONFLICT (env_id) WHERE customer_type = 'institution'
           DO UPDATE SET updated_at = now()
           RETURNING id"#,
    )
    .bind(env_id)
    .fetch_one(&mut *conn)
    .await?;
    tracing::info!(env_id = %env_id, customer_id = %id, "seeded institution customer (F8 scout)");
    Ok(id)
}

/// Seed internal accounts for the given org/env if they don't exist.
/// Called when the `ledger` service is enabled for an org/env
/// (via the `sentin8:sys:service:updated` Bus event). Idempotent
/// skips accounts that already exist.
/// Every query runs on ONE acquired connection with the tenant context
/// set for the target env - RLS is enforced (per-service DSN, F1), so a
/// context-less query would return zero rows and silently skip all seeds.
pub async fn seed_internal_accounts(pool: &PgPool, env_id: Uuid) -> anyhow::Result<()> {
    use crate::handlers::set_tenant_context;
    // Explicit transaction (rule 2 - same-connection context): the context
    // is transaction-local (`set_config(..., true)`); on an autocommit
    // connection it evaporates between statements, `sentin8_context_initialized()`
    // evaluates false, and the `customers` INSERT policy rejects the
    // institution row (fail-closed) - the whole seed then fails with
    // "new row violates row-level security".
    let mut conn = pool.begin().await?;
    set_tenant_context(&mut conn, env_id).await?;

    // F8 institution scout: create-or-get the bank party for this env
    // FIRST, so every internal account is stamped with a real customer_id
    // (never NULL) in the same pass.
    let institution_customer_id = ensure_institution_customer(&mut conn, env_id).await?;

    // Use the env context for seeding (these are platform-level accounts).
    // In a multi-tenant system, each env gets its own set of internal accounts.
    for denom in SEED_DENOMINATIONS {
        for (nickname, account_key) in SEED_ACCOUNTS {
            // Check if this account already exists.
            let existing = sqlx::query(
                r#"SELECT id FROM accounts
                   WHERE env_id = $1
                     AND account_type = 'internal'
                     AND product_type = $2
                     AND denomination = $3
                     AND nickname = $4
                   LIMIT 1"#,
            )
            .bind(env_id)
            .bind(*account_key)
            .bind(*denom)
            .bind(*nickname)
            .fetch_optional(&mut *conn)
            .await;

            match existing {
                Ok(Some(_)) => { /* Already exists - skip */ }
                Ok(None) => {
                    // Create the internal account, owned by the institution
                    // party (F8 - customer_id is never NULL for internal
                    // accounts).
                    let account_id = Uuid::new_v4();
                    let result = sqlx::query(
                        r#"INSERT INTO accounts
                           (id, env_id, customer_id, product_id, account_type, product_type,
                            nickname, denomination, status)
                           VALUES ($1, $2, $6, NULL, 'internal', $3, $4, $5, 'active')
                           ON CONFLICT DO NOTHING"#,
                    )
                    .bind(account_id)
                    .bind(env_id)
                    .bind(*account_key)
                    .bind(*nickname)
                    .bind(*denom)
                    .bind(institution_customer_id)
                    .execute(&mut *conn)
                    .await;

                    match result {
                        Ok(_) => {
                            tracing::info!(account_id = %account_id, nickname, denom, account_key, "seeded internal account")
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, nickname, denom, "failed to seed internal account")
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "failed to check for existing seed account"),
            }
        }
    }

    tracing::info!("internal account seeding complete");
    conn.commit().await?;
    Ok(())
}

/// Payload of the `sentin8:sys:service:updated` event consumed from
/// Sentin8:Bus (stream family `sys`). The ledger only acts on events
/// where `service == "ledger"` and `enabled == true`.
#[derive(Debug, serde::Deserialize)]
pub struct ServiceUpdatedPayload {
    pub env_id: Uuid,
    pub service: String,
    pub enabled: bool,
    #[serde(default)]
    pub config: serde_json::Value,
}

/// Handle a `sentin8:sys:service:updated` event from Sentin8:Bus.
/// When `service == "ledger"` and `enabled == true`, seed the standard
/// set of internal bank accounts (interest, fees, penalties) for all
/// supported denominations, and seed the env's per-env policy sets.
/// Idempotent - safe to call multiple times. Other services' events
/// are ignored.
pub async fn seed_for_service_event(pool: &PgPool, msg: &sentin8::bus::contracts::Message) {
    // Event names use ALL-COLON segments (AGENTS.md event-naming rule).
    // NOTE: `sentin8:sys.service.updated` (dot) was a bug - sys emits
    // `sentin8:sys:service:updated`, so env-init never fired.
    if msg.event_type != "sentin8:sys:service:updated" {
        return;
    }
    let parsed: ServiceUpdatedPayload = match serde_json::from_value(msg.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "env-init: dropping malformed sys.service.updated payload");
            return;
        }
    };
    if parsed.service != "ledger" || !parsed.enabled {
        return;
    }

    // VDC-2 (design/sentin8-vertical-data-plane-contract.md §VDC.4): the
    // former "verify in sys_services" gate was a cross-database read that
    // never worked (the platform tables do not exist in the bank8
    // database - the seed was ALWAYS silently skipped). Provenance is now
    // structural: Bus's produce-side event-ownership gate guarantees only
    // `sentin8`-vertical workloads may mint `sentin8:sys:*` events, and
    // this consumer verifies the recorded `publisher_vertical` before
    // seeding (defense-in-depth belt to the structural suspenders).
    if let Err(reason) = sentin8::bus::client::BusClient::require_publisher(msg) {
        tracing::warn!(reason = %reason, "env-init: untrusted publisher - skipping seed");
        return;
    }

    // Shield per-env set seeding (VDC §VDC.6): the ledger's Shield engine
    // evaluates policies per-request env, and its boot-load only finds the
    // SYSTEM-env substrate rows - a tenant-env user request (staff SSO to
    // Bank8:Admin) would hit `no_set_for_env` fail-closed denial. Seed the
    // env's copy of the ledger's platform-origin sets from the SYSTEM-env
    // template BEFORE any user request can arrive in that env.
    if let Err(e) = seed_env_policy_sets(pool, parsed.env_id).await {
        tracing::warn!(error = %e, env_id = %parsed.env_id, "env-init: policy-set seed failed");
    }

    tracing::info!(
        env_id = %parsed.env_id,
        "env-init: seeding internal accounts (event-driven)"
    );
    if let Err(e) = seed_internal_accounts(pool, parsed.env_id).await {
        tracing::warn!(error = %e, env_id = %parsed.env_id, "env-init: failed");
    } else {
        tracing::info!(env_id = %parsed.env_id, "env-init: complete");
    }
}

/// Copy this service's `origin='platform'` policy sets from the SYSTEM-env
/// substrate template into the given env - the vertical-DB mirror of what
/// Sentin8:Sys does for the platform DB at env creation (sys handlers
/// `seeded per-env platform policy sets`). Idempotent: an existing
/// tenant-env row is never overwritten (`ON CONFLICT DO NOTHING`), so
/// operator-edited sets survive re-enable events.
async fn seed_env_policy_sets(pool: &PgPool, env_id: Uuid) -> anyhow::Result<()> {
    const SYSTEM_ENV_ID: uuid::Uuid = uuid::Uuid::from_u128(2);
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', 'm2m', 'sys:admin')")
        .bind(SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    let seeded = sqlx::query(
        r#"INSERT INTO sys.policy_sets
               (env_id, service, policy_set_name, description, policies, schema, origin, mode, version, enabled)
           SELECT $2, service, policy_set_name, description, policies, schema,
                  'platform', mode, 1, true
             FROM sys.policy_sets
            WHERE env_id = $1 AND service = $3 AND origin = 'platform' AND enabled
           ON CONFLICT (env_id, service, policy_set_name) DO NOTHING"#,
    )
    .bind(SYSTEM_ENV_ID)
    .bind(env_id)
    .bind("bank8:ledger")
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    if seeded > 0 {
        tracing::info!(env_id = %env_id, sets = seeded, "env-init: seeded per-env policy sets");
    }
    Ok(())
}
