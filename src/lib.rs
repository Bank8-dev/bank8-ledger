// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Ledger - library re-exports for integration tests.

pub mod auth;
pub mod config;
pub mod cron_client;
pub mod func_hooks;
pub mod handlers;
pub mod ledger_aliases;
pub mod modules;
pub mod openapi;

// The utoipa dump for registration::print - mirrored from main.rs; the
// lib crate compiles registration::print too (test harnesses embedding
// via #[path] never invoke it, so the pointer is referenced, not run).
static OPENAPI_DUMP: fn() -> serde_json::Value = || {
    use utoipa::OpenApi as _;
    serde_json::to_value(openapi::LedgerOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
};

pub mod policy;
pub mod registration;
pub mod server;
pub mod statements;
pub mod tenant_snapshot;
pub mod types;
