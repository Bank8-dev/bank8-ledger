// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Ledger configuration loaded from environment variables.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

/// Ledger configuration loaded from environment variables.
#[derive(Clone)]
pub struct LedgerConfig {
    pub port: u16,
    pub database_url: String,
    pub sentin8_auth_issuer: String,
    pub sentin8_auth_jwks_url: String,
    pub sentin8_bus_url: String,
    pub sentin8_func_url: String,
    /// Certificate-presenting Func client (CERTFREE-4F — the `ledger`
    /// workload certificate presents in the TLS handshake). Built at
    /// boot; `None` degrades the hook lanes loudly.
    pub func_client: Option<sentin8_func_sdk::client::FuncClient>,
    /// Static token for the proxy-back CallbackConfig (the token Func
    /// presents BACK to ledger's internal func-host API — a separate
    /// contract from the Func client's own auth).
    pub sentin8_func_token: String,
    pub sentin8_cron_url: String,
    pub sentin8_cron_token: String,
    /// Sentin8:Flow base URL — the per-account-period statement regeneration
    /// workflow trigger (design §10). The client rides the boot-installed
    /// `ledger` workload transport (CERTFREE-4V — no M2M token exists);
    /// the static token is the proxy-back callback credential.
    pub sentin8_flow_url: String,
    pub sentin8_flow_token: String,
    /// Sentin8:Storage base URL — statement document uploads (design §10).
    pub sentin8_storage_url: String,
    pub stream_family: String,
    /// Story — Stat config for Ledger telemetry.
    pub sentin8_stat_url: String,
    pub sentin8_stat_property_id: uuid::Uuid,
    /// Shared Auth client — constructed once so the discovery and JWKS
    /// caches are reused across every request (5-minute TTL each).
    /// Cloning is cheap (the caches live behind an `Arc`).
    pub sentin8_auth_client: AuthClient,
    /// Certificate-presenting transport for the service's own
    /// workload identity (CERTFREE-4V — no M2M token exists): the
    /// `ledger` certificate presents in the TLS handshake — the
    /// receiving service's TLS layer authenticates it and the
    /// enroll-published registry map authorizes the scopes.
    pub m2m_http: Option<reqwest::Client>,
    /// Certificate-presenting transport for the `ledger-storage`
    /// workload (statement document uploads to Sentin8:Storage —
    /// design §10). Distinct from `m2m_http` because the scope grants
    /// differ (`sentin8:storage:env:write`/`read` vs the domain scopes).
    pub storage_http: Option<reqwest::Client>,
}

/// Manual `Debug` — never logs the transport internals.
impl std::fmt::Debug for LedgerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerConfig")
            .field("port", &self.port)
            .field("database_url", &"<redacted>")
            .field("sentin8_auth_issuer", &self.sentin8_auth_issuer)
            .field("stream_family", &self.stream_family)
            .field("m2m_http", &self.m2m_http.is_some())
            .finish_non_exhaustive()
    }
}

impl LedgerConfig {
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env::var("BANK8_LEDGER_PORT")
                .expect("BANK8_LEDGER_PORT must be set by captain")
                .parse()
                .expect("BANK8_LEDGER_PORT must be a valid u16"),
            database_url: env::var("BANK8_LEDGER_DATABASE_URL").unwrap_or_else(|_| {
                env::var("DATABASE_URL").unwrap_or_else(|_| {
                    sentin8::config::Sentin8Config::default_database_url().to_string()
                })
            }),
            sentin8_auth_issuer: env::var("SENTIN8_AUTH_ISSUER")
                .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url()),
            sentin8_func_url: env::var("SENTIN8_FUNC_URL")
                .unwrap_or_else(|_| cfg.sentin8_func_url()),
            func_client: None,
            sentin8_func_token: env::var("SENTIN8_FUNC_TOKEN")
                .unwrap_or_else(|_| "ledger-dev".into()),
            sentin8_cron_url: env::var("SENTIN8_CRON_URL")
                .unwrap_or_else(|_| cfg.sentin8_cron_url()),
            sentin8_cron_token: env::var("SENTIN8_CRON_TOKEN")
                .unwrap_or_else(|_| "ledger-dev".into()),
            sentin8_flow_url: env::var("SENTIN8_FLOW_URL")
                .unwrap_or_else(|_| cfg.sentin8_flow_url()),
            sentin8_flow_token: env::var("SENTIN8_FLOW_TOKEN")
                .unwrap_or_else(|_| "ledger-dev".into()),
            sentin8_storage_url: env::var("SENTIN8_STORAGE_URL")
                .unwrap_or_else(|_| cfg.sentin8_storage_url()),
            // Design §11: the ledger stream family is `ledger`
            // (`bus:{envId}:ledger`) — one family for the outbox relay,
            // the REST-produce paths, and every consumer.
            stream_family: env::var("BANK8_LEDGER_STREAM_FAMILY")
                .unwrap_or_else(|_| "ledger".into()),
            sentin8_stat_url: env::var("SENTIN8_STAT_URL")
                .unwrap_or_else(|_| cfg.sentin8_stat_url()),
            sentin8_stat_property_id: env::var("BANK8_LEDGER_STAT_PROPERTY_ID")
                .ok()
                .and_then(|s| uuid::Uuid::parse_str(&s).ok())
                .unwrap_or_else(|| {
                    uuid::Uuid::parse_str("a0000000-0000-0000-0000-000000000002").unwrap()
                }),
            sentin8_auth_client: AuthClient::new(ClientOptions {
                base_url: env::var("SENTIN8_AUTH_ISSUER")
                    .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
            m2m_http: None,
            storage_http: None,
        }
    }

    /// Token for the proxy-back CallbackConfig — the static
    /// `SENTIN8_FUNC_TOKEN` env value (the token Func presents BACK to
    /// ledger's internal func-host API; NOT the Func client's own
    /// auth, which is the certificate).
    pub async fn func_token(&self) -> String {
        self.sentin8_func_token.clone()
    }

    /// Token for Sentin8:Cron calls — the static `SENTIN8_CRON_TOKEN`
    /// env value (Cron authenticates bearer tokens).
    pub async fn cron_token(&self) -> String {
        self.sentin8_cron_token.clone()
    }
}
