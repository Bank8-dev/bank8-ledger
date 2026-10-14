// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Auth token verification for Ledger.
//! Re-exports the shared types from the sentin8-auth-client SDK and provides
//! thin wrappers matching the original Ledger call sites (taking `&LedgerConfig` + `&HeaderMap`).
//!  : step 5 is the ONLY gate (policy design §4.3). The
//! `require_any_scope` helper is gone — every handler verifies the token
//! (steps 1–4) with [`verify_token`], then evaluates a
//! `bank8:ledger:<resource>:<action>` Shield action via `crate::policy::require`
//! (`EvalTarget::new(...)`). Platform sets mirror the same scope vocabulary
//! over the LIVE effective scope set, so authorization behavior for
//! scope-holding callers is unchanged while Shield (roles/relations/attrs)
//! becomes the decision.

use axum::http::{HeaderMap, StatusCode};

use crate::config::LedgerConfig;

pub use sentin8::auth::client::AuthContext;

/// Verify the Bearer token and return the auth context (steps 1–4: identity
/// + signature + expiry + tenant). NO scope check — step 5
/// (`crate::policy::require`) is the authorization decision.
pub async fn verify_token(
    config: &LedgerConfig,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    sentin8::auth::client::verify_bearer_token(&config.sentin8_auth_client, headers).await
}
