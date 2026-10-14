// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Func integration — Ledger calls Func for contract hooks.
//! Hook types:
//! - `pre_posting` — runs before each posting instruction is committed
//! - `post_posting` — runs after a posting batch is committed
//! - `scheduled_event` — runs on scheduled events (interest accrual, fees, etc.)
//! - `activation` — runs when an account is activated (PENDING → OPEN)
//! - `deactivation` — runs when an account is deactivated (OPEN → CLOSED)
//! Func proxy-calls back to Ledger's internal API for host functions (get
//! account, get balance, set flag, etc.) via the CallbackConfig.

use sentin8_func_sdk::client::{CallbackConfig, ExecuteRequest, FuncClient};

/// Call a Func hook for a posting instruction.
/// `module_id` is the WASM module ID from the product version's `sentin8_func_version_id`.
/// `hook` is the hook name (e.g. "pre_posting").
/// `context` is the JSON context passed to the WASM module.
pub async fn call_hook(
    client: &FuncClient,
    module_id: &str,
    hook: &str,
    context: serde_json::Value,
    callback_base_url: Option<&str>,
    callback_auth_token: Option<&str>,
    callback_internal_path: Option<&str>,
) -> Result<serde_json::Value, String> {
    let cb = if let (Some(url), Some(token), Some(path)) = (callback_base_url, callback_auth_token, callback_internal_path) {
        Some(CallbackConfig {
            base_url: url.to_string(),
            auth_token: token.to_string(),
            internal_path: path.to_string(),
            host_functions: std::collections::HashMap::new(),
        })
    } else {
        None
    };
    let req = ExecuteRequest {
        hook: hook.to_string(),
        context,
        callback_config: cb,
    };
    let result = client.execute(module_id, &req).await
        .map_err(|e| format!("func execute {hook}: {e}"))?;
    Ok(result)
}

/// Alias for [`call_hook`] with a raw context (LEDG-COMPLETE :
/// `POST /v1/contracts:simulate` passes synthetic account state through the
/// same proxy-back pipeline). Same behavior, clearer call-site intent.
pub async fn call_hook_raw(
    client: &FuncClient,
    module_id: &str,
    hook: &str,
    context: serde_json::Value,
    callback_base_url: Option<&str>,
    callback_auth_token: Option<&str>,
    callback_internal_path: Option<&str>,
) -> Result<serde_json::Value, String> {
    call_hook(client, module_id, hook, context, callback_base_url, callback_auth_token, callback_internal_path).await
}

/// Re-run the post_posting hook for a previously committed batch (
/// post-posting republisher). Best-effort: returns whether the hook was
/// re-invoked, never fails the caller (the batch is already committed).
pub async fn republish_post_posting(
    config: &crate::config::LedgerConfig,
    env_id: uuid::Uuid,
    posting_id: &str,
    module_id: &str,
) -> bool {
    if config.sentin8_func_url.is_empty() || module_id.is_empty() {
        return false;
    }
    let Ok(pid) = posting_id.parse::<uuid::Uuid>() else { return false; };
    // Certificate-presenting client (CERTFREE-4F) — the `ledger`
    // workload certificate presents in the TLS handshake; the proxy-back
    // callback token is a separate contract (the token Func presents
    // BACK to ledger's internal func-host API).
    let Some(client) = config.func_client.clone() else {
        tracing::warn!(posting_id, module_id, "post_posting republish skipped: Func transport absent (workload certificate not provisioned)");
        return false;
    };
    let base = callback_base_url(config);
    let token = config.func_token().await;
    let ctx = post_posting_context(pid, posting_id, 0);
    match call_hook(&client, module_id, "post_posting", ctx, Some(&base), Some(&token), Some("/v1/internal/func-host")).await {
        Ok(_) => {
            tracing::info!(posting_id, module_id, env_id = %env_id, "post_posting hook republished");
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, posting_id, module_id, "post_posting republish failed (non-fatal)");
            false
        }
    }
}

/// Build the pre-posting hook context for a posting instruction.
pub fn pre_posting_context(
    account_id: uuid::Uuid,
    product_id: Option<uuid::Uuid>,
    instruction: &crate::handlers::postings::PostingInstruction,
    current_balance: rust_decimal::Decimal,
) -> serde_json::Value {
    serde_json::json!({
        "hook": "pre_posting",
        "account_id" : account_id,
        "product_id" : product_id,
        "instruction_type" : instruction.instruction_type,
        "debit_account" : instruction.debit_account,
        "credit_account" : instruction.credit_account,
        "amount": instruction.amount,
        "denomination": instruction.denomination,
        "current_balance" : current_balance.to_string(),
    })
}

/// Build the post-posting hook context for a completed batch.
pub fn post_posting_context(
    posting_id: uuid::Uuid,
    batch_id: &str,
    instruction_count: usize,
) -> serde_json::Value {
    serde_json::json!({
        "hook": "post_posting",
        "posting_id" : posting_id,
        "batch_id" : batch_id,
        "instruction_count" : instruction_count,
    })
}

/// Build the scheduled event hook context.
pub fn scheduled_event_context(
    account_id: uuid::Uuid,
    product_id: Option<uuid::Uuid>,
    schedule_type: &str,
    current_balance: rust_decimal::Decimal,
) -> serde_json::Value {
    serde_json::json!({
        "hook": "scheduled_event",
        "account_id" : account_id,
        "product_id" : product_id,
        "schedule_type" : schedule_type,
        "current_balance" : current_balance.to_string(),
    })
}

/// Build the activation hook context (PENDING → OPEN).
pub fn activation_context(
    account_id: uuid::Uuid,
    product_id: Option<uuid::Uuid>,
    denomination: &str,
) -> serde_json::Value {
    serde_json::json!({
        "hook": "activation",
        "account_id" : account_id,
        "product_id" : product_id,
        "denomination": denomination,
    })
}

/// Build the deactivation hook context (OPEN → CLOSED).
pub fn deactivation_context(
    account_id: uuid::Uuid,
    product_id: Option<uuid::Uuid>,
    final_balance: rust_decimal::Decimal,
) -> serde_json::Value {
    serde_json::json!({
        "hook": "deactivation",
        "account_id" : account_id,
        "product_id" : product_id,
        "final_balance" : final_balance.to_string(),
    })
}

/// Base URL Sentin8:Func proxy-calls back to (the `CallbackConfig.base_url`).
/// Derived from the service's externally routable origin
/// `SENTIN8_LEDGER_PUBLIC_URL` when set, else the standard platform domain
/// derivation `bank8-ledger.{env}.{org}.{tld}` from `SENTIN8_DOMAIN`. The
/// old `http://localhost:{port}` form only worked for co-located Func and
/// broke every TLS-terminated deployment.
pub fn callback_base_url(config: &crate::config::LedgerConfig) -> String {
    if let Ok(public) = std::env::var("SENTIN8_LEDGER_PUBLIC_URL") {
        if !public.trim().is_empty() {
            return public.trim().trim_end_matches('/').to_string();
        }
    }
    let domain = std::env::var("SENTIN8_DOMAIN").unwrap_or_default();
    if domain.trim().is_empty() {
        return format!("http://localhost:{}", config.port);
    }
    // SENTIN8_DOMAIN is the platform root (e.g. `sentin8.local`); the
    // service's hostname follows the uniform hierarchy `{service}.{env}.{org}.{tld}`
    // — platform services are the `ops` env of the `sys` org.
    format!("https://bank8-ledger.ops.sys.{}", domain.trim())
}