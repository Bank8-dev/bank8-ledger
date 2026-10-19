// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Policy integration for Bank8:Ledger.
//! Thin re-export of the shared bridge (`sentin8::shield::runtime`) - the
//! consolidated implementation every platform + vertical service uses.
//! Nothing is service-specific here beyond the colon service_type.
//! - boot wiring is shell-owned (policy design §4.2b): services only copy
//! `core.admin.policy` into their state;
//! - `require_policy` - step 5 glue: the FULL live evaluation (live
//! effective scopes §3.1d + roles + relation slice §3.1c + principal
//! attrs §3.1b), enforced deny → HTTP 403;
//! - `policy_admin_router` - the uniform §3.6 admin surface mounted in
//! `server.rs`, over the same engine instance the request path evaluates.
//! Ledger authorization model: ledger §6.1 (one engine, three models
//! RBAC/ABAC/ReBAC all Shield; RLS stays the tenant-isolation barrier).

#[allow(unused_imports)]
pub use sentin8::shield::runtime::{
    check_policy, engine_for, policy_bus_client, request_ctx, spawn_hot_reload,
};
pub use sentin8::shield::PolicyEngine as Engine;

/// Step 5 for ledger: verify (steps 1-4) already ran; evaluate + 403 on
/// enforced deny. Handlers call this instead of any JWT scope check
/// (policy design §4.3 - no per-service scope checks remain).
pub use sentin8::shield::runtime::require_policy as require;
