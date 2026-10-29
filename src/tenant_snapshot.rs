// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Sys tenant-snapshot client (VDC §VDC.5 / isolation-design §10).
//!
//! The staff directory reads (`GET /v1/customers?env_id=<foreign env>`)
//! must verify that the caller's env belongs to the requested env's
//! org - the former cross-database `sentin8.sys_environments` joins
//! never existed in the vertical's own database and failed
//! every such request. The sanctioned on-demand read is Sys's
//! tenant-snapshot API (`GET /v1/tenants/{env_id}`) via the
//! cert-presenting `bank8-ledger-sys` workload (CERTFREE-4V - no M2M
//! token; the `sentin8:sys:tenants:read` scope rides the
//! enroll-published registry map). Mirrors the fdx consumer's client
//! (peers cannot share a crate).

/// Fetch an env's org id from Sys's tenant-snapshot API
/// (`GET /v1/tenants/{env_id}`, workload `bank8-ledger-sys`).
/// `Ok(None)` = 404 (env unknown) - the caller treats it as a failed
/// membership check (fail-closed). `Err` = transport/5xx - also
/// fail-closed at the caller.
pub async fn env_org_id(env_id: uuid::Uuid) -> Result<Option<uuid::Uuid>, String> {
    let cfg = sentin8::config::Sentin8Config::from_env();
    let ca_path = sentin8::auth::m2m::platform_ca_path();
    let cert = sentin8::auth::m2m::ensure_workload_certificate(
        &cfg.sentin8_auth_issuer(),
        "bank8-ledger-sys",
        &ca_path,
    )
    .await
    .map_err(|e| format!("workload certificate: {e}"))?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    let http = sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| format!("transport: {e}"))?;
    let url = format!(
        "{}/v1/tenants/{}",
        cfg.sentin8_sys_url().trim_end_matches('/'),
        env_id
    );
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("sys snapshot fetch: {e}"))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(format!("sys snapshot fetch: {status}"));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let org_id = body
        .get("org_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok());
    Ok(org_id)
}
