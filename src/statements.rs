// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Statement document storage + the per-account-period Flow regeneration
//! workflow trigger (design §10).
//!
//! Split from the schedule handler so the document rendering, Storage
//! upload, and Flow trigger are unit-testable without a schedule handler.
//! The statement *row* is written by `handlers::schedules::generate_statements`
//! in the same transaction as the posting sums; this module owns the
//! document bytes and the retryable regen path.

use crate::config::LedgerConfig;

/// Bucket the statement documents live under - the same bucket the FDX
/// statement-download path serves signed read links from
/// (statement_download.rs: `statements/objects/{envId}/{accountId}/…`).
pub(crate) const STATEMENTS_BUCKET: &str = "statements";

/// The Flow logic id for per-account-period statement regeneration
/// (design §10). Correlation = `account_id:period` so Flow's pending-dedupe
/// partial index makes regenerate-idempotency structural.
pub(crate) const REGEN_LOGIC_ID: &str = "statement-regen";

/// Statement document writer against Sentin8:Storage. Rides the
/// cert-presenting `ledger-storage` workload transport
/// (config.storage_http - CERTFREE-4V: the certificate presents in the
/// TLS handshake, Storage's TLS layer authenticates it, and the
/// registry map authorizes the env-read/write scopes; no token exists).
pub(crate) struct StatementStorage {
    base_url: String,
    /// The `ledger-storage` workload transport; `None` until boot mints
    /// it (uploads fail loud - never a token fallback).
    http: Option<reqwest::Client>,
}

impl StatementStorage {
    /// Build from the ledger config: the Storage base URL from the shared
    /// platform derivation (§4.9) + the boot-installed `ledger-storage`
    /// workload transport (cert-bound; design §10).
    pub(crate) fn from_config(config: &LedgerConfig) -> Self {
        Self {
            base_url: config.sentin8_storage_url.clone(),
            http: config.storage_http.clone(),
        }
    }

    /// Upload the rendered statement document under the statements bucket.
    /// Object path is env-prefixed (`objects/{envId}/{account}/{id}.json`)
    /// so the FDX signed-link lookup finds it.
    pub(crate) async fn put_statement(
        &self,
        object_path: &str,
        data: Vec<u8>,
    ) -> Result<(), String> {
        // The bucket prefix lives in the object path (Storage serves the
        // `statements` bucket via `statements/objects/…` - the same shape
        // FDX statement_download.rs reads back).
        let _ = STATEMENTS_BUCKET;
        let Some(http) = &self.http else {
            return Err("ledger-storage workload transport absent".into());
        };
        let resp = http
            .put(format!(
                "{}/v1/storage/objects/{object_path}",
                self.base_url.trim_end_matches('/')
            ))
            .header("Content-Type", "application/json")
            .body(data)
            .send()
            .await
            .map_err(|e| format!("storage statement upload: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "storage statement upload: status {}",
                resp.status()
            ));
        }
        Ok(())
    }
}

/// Trigger the per-account-period regeneration workflow in Sentin8:Flow
/// (design §10). Best-effort: a Flow outage must not fail the scheduled
/// statement run - the statement row is already committed, and the next
/// period's run (or a manual re-drive) retries.
///
/// Correlation = `account_id:period` rides Flow's pending-dedupe partial
/// index `(env_id, logic_id, correlation_id) WHERE state = 'pending'`.
pub(crate) async fn trigger_regen_workflow(
    state: &crate::handlers::AppState,
    env_id: uuid::Uuid,
    account_id: uuid::Uuid,
    period_label: &str,
) {
    use sentin8_flow_sdk::client::{CallbackConfig, CreateWorkflowRequest, LogicVersion};

    // Cert-presenting Flow client (CERTFREE-4V): rides the boot-installed
    // `ledger` workload transport - Flow's TLS layer authenticates the
    // handshake and its certificate-first gate resolves the workload.
    // A missing transport degrades to the documented dev-plain fallback
    // (Flow rejects it loudly at the authorization gate).
    let client = match &state.config.m2m_http {
        Some(http) => sentin8_flow_sdk::client::FlowClient::from_transport(
            &state.config.sentin8_flow_url,
            sentin8::middleware::http_client::Sentin8HttpClient::from_client(http.clone()),
        ),
        None => sentin8_flow_sdk::client::FlowClient::new_dev_plain(
            state.config.sentin8_flow_url.clone(),
        ),
    };
    let correlation = format!("{account_id}:{period_label}");
    let req = CreateWorkflowRequest {
        domain: "ledger".into(),
        logic: LogicVersion {
            logic_id: REGEN_LOGIC_ID.into(),
            version: 1,
            steps: vec![sentin8_flow_sdk::client::StepDef {
                name: "render_statement".into(),
                kind: "BasicStep".into(),
                next_step: None,
                config: Some(serde_json::json!({
                    "account_id": account_id, "period": period_label,
                })),
                on_error: None,
            }],
            correlation_id_func: None,
            expected_parameters: Some(vec!["account_id".into(), "period".into()]),
        },
        input: serde_json::json!({
            "account_id": account_id, "period": period_label, "env_id": env_id,
        }),
        callback_config: CallbackConfig {
            base_url: format!("http://localhost:{}", state.config.port),
            auth_token: state.config.sentin8_flow_token.clone(),
            internal_path: "/v1/internal/statements/regen".into(),
            host_functions: std::collections::HashMap::new(),
        },
        correlation_id: Some(correlation),
    };
    match client.create_workflow(&req).await {
        Ok(_) => {
            tracing::info!(account_id = %account_id, period = %period_label, "statement regen workflow created");
        }
        Err(e) => {
            tracing::warn!(error = %e, account_id = %account_id, "statement regen workflow create failed (non-fatal - statement row is committed)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regen_logic_id_is_stable() {
        // The logic id is a wire-visible contract (the worker/FDX docs pin
        // `statement-regen`); renaming it is a workflow-surface break.
        assert_eq!(REGEN_LOGIC_ID, "statement-regen");
    }

    #[test]
    fn statements_bucket_matches_fdx_download_path() {
        // FDX statement_download.rs reads `statements/objects/{env}/{acct}/{id}.pdf`
        // via a signed link on this bucket - the bucket name must not drift.
        assert_eq!(STATEMENTS_BUCKET, "statements");
    }
}
