// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Ledger — core ledger, posting engine, product library.
//! See `services/ledger/DESIGN.md`.
//! Boot runs on the platform `sentin8-shell` crate (design
//! `sentin8/design/sentin8-sentin8-shell-technical-design.md`): registration
//! flag, PQ provider, config, capped pool, PG18 check, state binding, OpenAPI
//! merge, middleware stack and PQ-TLS listener are owned by the shell. This
//! binary supplies only its registration data, state and routes.

// allocation in the process routes through it). Rationale in the workspace
// Cargo.toml: glibc's per-thread arenas fragment under the many-worker tokio
// runtime and never return memory; measured 4 MB+ RSS growth per request
#[allow(dead_code)]
mod auth;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod cron_client;
#[allow(dead_code)]
mod func_hooks;
#[allow(dead_code)]
mod handlers;
#[allow(dead_code)]
mod modules;
#[allow(dead_code)]
mod openapi;
mod policy;
mod registration;
#[allow(dead_code)]
mod server;
#[allow(dead_code)]
mod statements;
#[allow(dead_code)]
mod tenant_snapshot;
#[allow(dead_code)]
mod types;

use utoipa::OpenApi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("bank8:ledger", "BANK8_LEDGER")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            .with_router(|router, _state| server::routes(router))
            .with_openapi(openapi::LedgerOpenApi::openapi()),
    )
    .await
}
