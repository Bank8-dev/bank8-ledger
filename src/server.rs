// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for Ledger.

use std::sync::Arc;

use axum::routing::{get, post, put};

use crate::handlers::{self, AppState};

/// Build a cert-presenting HTTP transport for `workload` (CERTFREE-4V,
/// auth DESIGN §4.3f): mint-or-load the Acme-issued pair and wrap it in
/// a reqwest client. The receiving service's TLS layer authenticates the
/// handshake and the enroll-published registry map authorizes the
/// scopes - no bearer token exists on this path.
///
/// # Errors
/// Returns the certificate-ensure or transport-build failure (the
/// caller logs and degrades).
async fn build_workload_http(auth_issuer: &str, workload: &str) -> anyhow::Result<reqwest::Client> {
    let cert = sentin8::auth::m2m::ensure_workload_certificate(
        auth_issuer,
        workload,
        &sentin8::auth::m2m::platform_ca_path(),
    )
    .await?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| anyhow::anyhow!("workload '{workload}' transport: {e}"))
}

pub async fn build_state(
    core: sentin8::shell::ServiceCore,
) -> anyhow::Result<crate::handlers::AppState> {
    let mut config = crate::config::LedgerConfig::from_env();

    // Cert-presenting Bus client (CERTFREE-4V): the `ledger` workload
    // CERTIFICATE is the identity - no DCR, no token (auth DESIGN
    // §4.3f); the mint retries while the fleet boots.
    let bus_client = loop {
        match sentin8::bus::client::BusClient::for_workload(
            &config.sentin8_bus_url,
            &config.sentin8_auth_issuer,
            "ledger",
        )
        .await
        {
            Ok(c) => break c,
            Err(e) => {
                tracing::debug!(error = %e, "ledger bus client: certificate not ready yet");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    };

    // The service's own workload transport (CERTFREE-4V): the
    // `ledger` certificate presents in the TLS handshake - the
    // receiving service's TLS layer authenticates it and the registry
    // map authorizes the scopes. Non-fatal on failure - the Func/Cron
    // clients keep the static dev tokens until the next boot.
    match build_workload_http(&config.sentin8_auth_issuer, "ledger").await {
        Ok(http) => config.m2m_http = Some(http),
        Err(e) => tracing::warn!(error = %e, "ledger workload transport unavailable - degraded"),
    }

    // Cert-presenting transport for statement document uploads (design
    // §10): the `ledger-storage` workload's certificate holds the Storage
    // env-read/write scopes; the scheduled statement step PUTs the
    // rendered document and the FDX statement_download path reads it back
    // via a signed link. Non-fatal - statement generation degrades when
    // the transport is missing.
    match build_workload_http(&config.sentin8_auth_issuer, "ledger-storage").await {
        Ok(http) => config.storage_http = Some(http),
        Err(e) => {
            tracing::warn!(error = %e, "ledger-storage transport unavailable - statement uploads degraded")
        }
    }

    // CERTFREE-4F: the direct Func lanes (hook republish) present the
    // `ledger` workload certificate - Func's cert-first gate resolves it
    // against the registry map. None → the hook lanes degrade loudly.
    // (The proxy-back CallbackConfig token stays - the token Func
    // presents BACK to ledger's internal func-host API.)
    if !config.sentin8_func_url.is_empty() {
        match sentin8::auth::m2m::ensure_workload_certificate(
            &config.sentin8_auth_issuer,
            "ledger",
            &sentin8::auth::m2m::platform_ca_path(),
        )
        .await
        {
            Ok(cert) => {
                match sentin8_func_sdk::client::FuncClient::with_workload_identity(
                    &config.sentin8_func_url,
                    &cert.ca_cert_path,
                    &cert.cert_path,
                    &cert.key_path,
                ) {
                    Ok(c) => config.func_client = Some(c),
                    Err(e) => {
                        tracing::warn!(error = %e, "ledger func transport build failed - hook lanes degraded")
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "ledger func certificate not ready - hook lanes degraded")
            }
        }
    }

    // ── Sentin8:Policy ──────────────────────────────
    // Load the service's policy sets; an unparsable policy text REFUSES TO
    // START (fail-closed at boot, design §3.3). Hot-reload consumes the
    // `policy` stream as a direct consumer (design §3.2); deny/would-deny
    // decisions emit to Stat (§4.2f). The engine is stored in AppState so
    // handlers gate via `policy::require` (step 5 is the ONLY gate).
    // ── Sentin8:Policy (§4.2b - shell-owned boot): consume the
    // engine the shell booted in step 8 - no second engine, consumer, or
    // DCR registration here.
    let policy_engine = core.admin.policy.clone();

    let state = AppState {
        config: Arc::new(config),
        pool: core.pool.clone(),
        bus_client,
        policy: policy_engine.clone(),
        effective_param_cache: Arc::new(handlers::params::EffectiveParamCache::default()),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "bank8:ledger".to_string(),
            pool: core.pool.clone(),
            policy: policy_engine,
            auth_client: Arc::new(core.config.sentin8_auth_client.clone()),
        },
    };

    // Spawn the Sentin8:Bus consumer for event-driven env-init. Subscribes
    // to the `sys` stream family and reacts to `sentin8:sys.service.updated`
    // by seeding internal accounts when `bank8-ledger` is enabled.
    // Uses a clone of the Bus client (the M2M token source is shared via
    // Arc internally) so the consumer and AppState can both call Bus.
    handlers::event_consumer::spawn(core.pool.clone(), state.bus_client.clone());

    Ok(state)
}

/// Add this service's routes onto the shell-provided router. The shell
/// owns the boot sequence, state binding, OpenAPI merge and the standard
/// middleware stack; this adds ONLY routes (including the service's own
/// `/v1/health` - custom payload).
pub fn routes(
    router: axum::Router<crate::handlers::AppState>,
) -> axum::Router<crate::handlers::AppState> {
    router
        .route("/v1/health", get(handlers::health))
        // ── Sentin8:Policy admin API (§3.6 - shared
        // implementation; handlers generic over this AppState).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<handlers::AppState>),
        )
        // ── Account API (v1 + v2) ─────────────────────────────────────────
        .route(
            "/v1/accounts",
            post(handlers::accounts::create_account).get(handlers::accounts::list_accounts),
        )
        .route(
            "/v1/accounts/{id}",
            get(handlers::accounts::get_account).put(handlers::accounts::update_account),
        )
        .route(
            "/v1/accounts/{id}/balances",
            get(handlers::accounts::get_account_balances),
        )
        .route(
            "/v1/accounts/{id}/transactions",
            get(handlers::accounts::get_account_transactions),
        )
        .route(
            "/v1/accounts/{id}/statements",
            get(handlers::accounts::get_account_statements),
        )
        .route(
            "/v1/accounts/{id}/schedules",
            get(handlers::schedules::list_account_schedules),
        )
        // ── Product API ────────────────────────────────────────────────────
        .route(
            "/v1/products",
            post(handlers::products::create_product).get(handlers::products::list_products),
        )
        .route(
            "/v1/products/{id}",
            get(handlers::products::get_product).put(handlers::products::update_product),
        )
        .route(
            "/v1/products/{id}/activate",
            post(handlers::products::activate_product),
        )
        .route(
            "/v1/products/{id}/versions",
            post(handlers::products::create_product_version)
                .get(handlers::products::list_product_versions),
        )
        // ── Posting API ───────────────────────────────────────────────────
        .route("/v1/postings", post(handlers::postings::create_posting))
        .route(
            "/v1/postings/async",
            post(handlers::postings::create_posting_async),
        )
        .route("/v1/postings/{id}", get(handlers::postings::get_posting))
        .route(
            "/v1/postings/{id}/instructions",
            get(handlers::postings::get_posting_instructions),
        )
        // ── Schedule / Job / Calendar API ──────────────────────────────────
        .route(
            "/v1/schedules",
            post(handlers::schedules::create_schedule).get(handlers::schedules::list_schedules),
        )
        .route("/v1/schedules/{id}", get(handlers::schedules::get_schedule))
        .route("/v1/jobs", get(handlers::schedules::list_jobs))
        .route("/v1/jobs/{id}", get(handlers::schedules::get_job))
        .route("/v1/jobs/{id}/retry", post(handlers::schedules::retry_job))
        .route(
            "/v1/jobs:batchRepublish",
            post(handlers::schedules::batch_republish_jobs),
        )
        .route(
            "/v1/calendars",
            post(handlers::schedules::create_calendar).get(handlers::schedules::list_calendars),
        )
        // ── Internal: Cron proxy-back ─────────────────────────────────────
        .route(
            "/v1/internal/schedules/run",
            post(handlers::schedules::internal_schedule_run),
        ) // ── Internal: Func proxy-back (host functions) ────────────────────
        .route(
            "/v1/internal/func-host",
            post(handlers::func_host::func_host),
        )
        // ── Internal: Flow proxy-back (statement regen, design §10) ──────
        .route(
            "/v1/internal/statements/regen",
            post(handlers::statement_regen::statement_regen_step),
        ) // ── Flag API ───────────────────────────────────────────────────────
        .route(
            "/v1/flag-definitions",
            post(handlers::flags::create_flag_definition)
                .get(handlers::flags::list_flag_definitions),
        )
        .route(
            "/v1/flags",
            post(handlers::flags::create_flag).get(handlers::flags::list_flags),
        )
        // ── Restriction API ────────────────────────────────────────────────
        .route(
            "/v1/restriction-definitions",
            post(handlers::restrictions::create_restriction_definition)
                .get(handlers::restrictions::list_restriction_definitions),
        )
        .route(
            "/v1/restriction-sets",
            post(handlers::restrictions::create_restriction_set)
                .get(handlers::restrictions::list_restriction_sets),
        )
        // ── Parameter API ─────────────────────────────────────────────────
        .route(
            "/v1/parameters",
            post(handlers::params::create_parameter).get(handlers::params::list_parameters),
        )
        .route(
            "/v1/parameter-values",
            post(handlers::params::create_parameter_value)
                .get(handlers::params::list_parameter_values),
        )
        .route(
            "/v1/parameter-values:viewEffective",
            get(handlers::params::view_effective_parameter),
        )
        .route(
            "/v1/parameter-value-hierarchy-nodes",
            post(handlers::params::create_hierarchy_node)
                .get(handlers::params::list_hierarchy_nodes),
        )
        // ── Customer API ──────────────────────────────────────────────────
        .route(
            "/v1/customers",
            post(handlers::customers::create_customer).get(handlers::customers::list_customers),
        )
        .route("/v1/customers/{id}", get(handlers::customers::get_customer))
        // .9: link a customer to an Auth user (called by Auth sign-up hook).
        .route(
            "/v1/customers/{id}/link-auth",
            post(handlers::customers::link_auth),
        )
        // ── Audit API ─────────────────────────────────────────────────────
        .route("/v1/audit", get(crate::ledger_aliases::audit_events_alias))
        // ── DLQ API ───────────────────────────────────────────────────────
        .route("/v1/dlq", get(handlers::postings::list_dlq))
        .route(
            "/v1/dlq/{id}/republish",
            post(handlers::postings::republish_dlq),
        )
        // ── Admin UI (RFW) ─────────────────────────────────────────────────
        .route(
            "/v1/admin/ui/{*page}",
            get(handlers::admin_ui::get_admin_ui),
        )
        // Admin data endpoints (RFW data_endpoint calls - Dash prepends /v1/admin).
        .route(
            "/v1/admin/products",
            get(crate::ledger_aliases::admin_list_products)
                .post(handlers::admin_ui::submit_product_form),
        )
        .route(
            "/v1/admin/products/{id}",
            get(crate::ledger_aliases::admin_get_product)
                .put(handlers::admin_ui::submit_product_edit),
        )
        .route(
            "/v1/admin/products/{id}/versions",
            get(crate::ledger_aliases::admin_list_product_versions)
                .post(handlers::admin_ui::submit_product_version),
        )
        .route(
            "/v1/admin/products/{id}/activate",
            post(crate::ledger_aliases::admin_activate_product),
        )
        .route(
            "/v1/admin/accounts",
            get(crate::ledger_aliases::admin_accounts)
                .post(handlers::admin_ui::submit_account_form),
        )
        .route(
            "/v1/admin/accounts/{id}",
            put(handlers::admin_ui::submit_account_edit),
        )
        .route(
            "/v1/admin/postings",
            get(handlers::postings::list_postings_batches)
                .post(handlers::admin_ui::submit_posting_form),
        )
        .route(
            "/v1/admin/schedules",
            get(crate::ledger_aliases::admin_list_schedules),
        )
        .route(
            "/v1/admin/jobs",
            get(crate::ledger_aliases::admin_list_jobs),
        )
        .route("/v1/admin/dlq", get(crate::ledger_aliases::list_dlq_alias))
        .route(
            "/v1/admin/dlq/{id}/republish",
            post(crate::ledger_aliases::admin_republish_dlq),
        )
        .route(
            "/v1/admin/dlq/{id}/discard",
            post(handlers::admin_ui::discard_dlq_entry),
        )
        .route(
            "/v1/admin/customers",
            get(crate::ledger_aliases::admin_customers),
        )
        .route("/v1/admin/audit", get(handlers::audit::list_audit_events))
        .route(
            "/v1/admin/parameters",
            get(crate::ledger_aliases::admin_parameters)
                .post(handlers::admin_ui::submit_parameter_form),
        )
        .route(
            "/v1/admin/restriction-sets",
            get(crate::ledger_aliases::admin_restriction_sets)
                .post(handlers::admin_ui::submit_restriction_form),
        )
        .route(
            "/v1/admin/restriction-definitions",
            get(crate::ledger_aliases::admin_restriction_definitions),
        )
        .route(
            "/v1/admin/flags",
            get(crate::ledger_aliases::admin_flags).post(handlers::admin_ui::submit_flag_form),
        )
        .route(
            "/v1/admin/flag-definitions",
            get(crate::ledger_aliases::admin_flag_definitions),
        )
        // Registration-declared summary/data endpoints (Dash DataTable fetches).
        .route(
            "/v1/admin/overview",
            get(crate::ledger_aliases::admin_overview),
        )
        .route(
            "/v1/admin/reconcile",
            get(handlers::admin_ui::admin_reconcile_summary),
        )
        .route(
            "/v1/admin/balances",
            get(handlers::admin_ui::admin_balances),
        )
        .route(
            "/v1/admin/settings",
            get(handlers::admin_ui::admin_settings),
        )
        .route(
            "/v1/admin/statements",
            get(handlers::admin_ui::admin_statements),
        )
        // Journal events
        .route(
            "/v1/journal-events",
            get(handlers::journal::list_journal_events),
        )
        .route(
            "/v1/journal-events/{id}",
            get(handlers::journal::get_journal_event),
        )
        .route(
            "/v1/journal-events/{id}/replay",
            post(handlers::journal::replay_journal_event),
        )
        // Adjustments + post-posting failures
        .route(
            "/v1/adjustments",
            post(handlers::adjustments::create_adjustment)
                .get(handlers::adjustments::list_adjustments),
        )
        .route(
            "/v1/adjustments/{id}",
            get(handlers::adjustments::get_adjustment),
        )
        .route(
            "/v1/adjustments/bulk-retry",
            post(handlers::adjustments::bulk_retry_adjustments),
        )
        .route(
            "/v1/post-posting-failures",
            get(handlers::adjustments::list_post_posting_failures),
        )
        .route(
            "/v1/post-posting-failures/{id}/republish",
            post(handlers::adjustments::republish_post_posting_failure),
        )
        // Balances v2
        .route(
            "/v2/balances/live",
            get(handlers::balances_v2::balances_v2_live),
        )
        .route(
            "/v2/balances/end",
            get(handlers::balances_v2::balances_v2_end),
        )
        .route(
            "/v2/balances/series",
            get(handlers::balances_v2::balances_v2_series),
        )
        // Processing groups
        .route(
            "/v1/processing-groups",
            get(handlers::processing_groups::list_processing_groups)
                .post(handlers::processing_groups::upsert_processing_group),
        )
        .route(
            "/v1/processing-groups/{id}/pause",
            post(handlers::processing_groups::pause_processing_group),
        )
        .route(
            "/v1/processing-groups/{id}/resume",
            post(handlers::processing_groups::resume_processing_group),
        )
        // Calendar events / periods / bookkeeping dates
        .route(
            "/v1/calendars/{id}/events",
            get(handlers::calendar::list_calendar_events)
                .post(handlers::calendar::create_calendar_event),
        )
        .route(
            "/v1/calendars/{id}/periods",
            get(handlers::calendar::list_calendar_periods)
                .post(handlers::calendar::create_calendar_period),
        )
        .route(
            "/v1/calendar/bookkeeping-date/{date}",
            get(handlers::calendar::get_bookkeeping_date)
                .put(handlers::calendar::upsert_bookkeeping_date),
        )
        // Schedule tags + account schedule tags
        .route(
            "/v1/schedule-tags",
            get(handlers::schedule_tags::list_schedule_tags)
                .post(handlers::schedule_tags::create_schedule_tag),
        )
        .route(
            "/v1/schedule-tags/{id}/assocs",
            post(handlers::schedule_tags::associate_schedule_tag),
        )
        .route(
            "/v1/account-schedule-tags",
            get(handlers::schedule_tags::list_account_schedule_tags),
        )
        .route(
            "/v1/accounts/{id}/schedule-tags",
            post(handlers::schedule_tags::upsert_account_schedule_tag),
        )
        // Plans
        .route(
            "/v1/plans",
            get(handlers::plans::list_plans).post(handlers::plans::create_plan),
        )
        .route("/v1/plans/{id}", get(handlers::plans::get_plan))
        .route(
            "/v1/plans/{id}/migrations",
            post(handlers::plans::migrate_plan),
        )
        .route(
            "/v1/account-plan-assocs",
            get(handlers::plans::list_plan_assocs).post(handlers::plans::create_plan_assoc),
        )
        // Contracts / simulation / supervisor contracts
        .route(
            "/v1/contract-modules",
            get(handlers::contracts::list_contract_modules),
        )
        .route(
            "/v1/contract-events",
            get(handlers::contracts::list_contract_events),
        )
        .route(
            "/v1/contracts/simulate",
            post(handlers::contracts::simulate_contract),
        )
        .route(
            "/v1/supervisor-contracts",
            get(handlers::contracts::list_supervisor_contracts)
                .post(handlers::contracts::create_supervisor_contract),
        )
        .route(
            "/v1/supervisor-contracts/{id}",
            get(handlers::contracts::get_supervisor_contract),
        )
        // Derived + global parameters
        .route(
            "/v1/derived-parameter-values",
            get(handlers::parameters_ext::get_derived_parameters),
        )
        .route(
            "/v1/global-parameters",
            get(handlers::parameters_ext::list_global_parameters)
                .post(handlers::parameters_ext::upsert_global_parameter),
        )
        .route(
            "/v1/global-parameters/{id}",
            get(handlers::parameters_ext::get_global_parameter),
        )
        // Internal accounts
        .route(
            "/v1/internal-accounts",
            get(handlers::internal_accounts::list_internal_accounts)
                .post(handlers::internal_accounts::create_internal_account),
        )
        .route(
            "/v1/internal-accounts/{id}",
            get(handlers::internal_accounts::get_internal_account),
        )
        // Account attributes + payment devices
        .route(
            "/v1/accounts/{id}/attributes",
            get(handlers::account_extras::list_account_attributes)
                .put(handlers::account_extras::upsert_account_attribute),
        )
        .route(
            "/v1/accounts/{id}/devices",
            get(handlers::account_extras::list_payment_devices)
                .post(handlers::account_extras::attach_payment_device),
        )
        // Customer update
        .route(
            "/v1/customers/{id}/update",
            put(handlers::customers::update_customer),
        )
        // Bulk batches
        .route(
            "/v1/account-migrations",
            post(handlers::bulk_batches::create_bulk_batch),
        )
        .route(
            "/v1/account-update-batches",
            get(handlers::bulk_batches::list_bulk_batches),
        )
        .route(
            "/v1/account-update-batches/{id}/bulk-retry",
            post(handlers::bulk_batches::bulk_retry_batch),
        )
        // Streaming catalog + action logs
        .route("/v1/streams", get(handlers::streams::list_streams))
        .route(
            "/v1/audit/action-logs",
            get(handlers::audit::list_action_logs),
        )
    // Traffic counter - counts every inbound request (excludes health checks).
}

/// Shared policy-admin surface accessor (§3.6) - the shared
/// handlers extract this service's admin state via [`HasPolicyAdmin`].
impl sentin8::shield::admin::HasPolicyAdmin for handlers::AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
