// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Annotated alias wrappers for Bank8:Ledger's duplicate-mount surface
//! (OAPEC design §2 rule 3): handlers bound at a SECOND real path get their
//! own annotation here (same handler body, alias path, same gates). The
//! canonical paths are annotated on the handlers themselves.

use crate::handlers::accounts::AccountResponse;
use crate::handlers::audit::AuditEventResponse;
use crate::handlers::customers::CustomerResponse;
use crate::handlers::flags::{FlagDefinitionResponse, FlagResponse};
use crate::handlers::params::ParameterResponse;
use crate::handlers::postings::{DlqRepublishAck, DlqResponse};
use crate::handlers::products::{ProductResponse, ProductVersionResponse};
use crate::handlers::restrictions::{RestrictionDefinitionResponse, RestrictionSetResponse};
use crate::handlers::schedules::{JobResponse, ScheduleResponse};
use crate::handlers::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;

/// `GET /v1/admin/accounts` - admin view of `GET /v1/accounts` (same
/// handler).
#[utoipa::path(
    get,
    path = "/v1/admin/accounts",
    responses(
        (status = 200, description = "Accounts (admin view)", body = Vec<AccountResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn admin_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::handlers::accounts::ListAccountsQuery>,
) -> axum::response::Response {
    match crate::handlers::accounts::list_accounts(State(state), headers, Query(q)).await {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `GET /v1/admin/overview` - the overview page's data (accounts-backed
/// summary; same handler as `GET /v1/accounts`).
#[utoipa::path(
    get,
    path = "/v1/admin/overview",
    responses(
        (status = 200, description = "Admin overview (accounts-backed summary)", body = Vec<AccountResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]
pub async fn admin_overview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::handlers::accounts::ListAccountsQuery>,
) -> axum::response::Response {
    match crate::handlers::accounts::list_accounts(State(state), headers, Query(q)).await {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `GET /v1/admin/customers` - admin view of `GET /v1/customers`.
#[utoipa::path(
    get,
    path = "/v1/admin/customers",
    responses(
        (status = 200, description = "Customers (admin view)", body = Vec<CustomerResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn admin_customers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::handlers::customers::ListCustomersQuery>,
) -> axum::response::Response {
    match crate::handlers::customers::list_customers(State(state), headers, Query(q)).await {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `GET /v1/admin/flag-definitions` - admin view of
/// `GET /v1/flag-definitions`.
#[utoipa::path(
    get,
    path = "/v1/admin/flag-definitions",
    responses(
        (status = 200, description = "Flag definitions (admin view)", body = Vec<FlagDefinitionResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn admin_flag_definitions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    match crate::handlers::flags::list_flag_definitions(State(state), headers).await {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `GET /v1/admin/flags` - admin view of `GET /v1/flags`.
#[utoipa::path(
    get,
    path = "/v1/admin/flags",
    responses(
        (status = 200, description = "Flags (admin view)", body = Vec<FlagResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn admin_flags(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::handlers::flags::ListFlagsQuery>,
) -> axum::response::Response {
    match crate::handlers::flags::list_flags(State(state), headers, Query(q)).await {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `GET /v1/admin/parameters` - admin view of `GET /v1/parameters`.
#[utoipa::path(
    get,
    path = "/v1/admin/parameters",
    responses(
        (status = 200, description = "Parameters (admin view)", body = Vec<ParameterResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn admin_parameters(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    match crate::handlers::params::list_parameters(State(state), headers).await {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `GET /v1/admin/restriction-definitions` - admin view of
/// `GET /v1/restriction-definitions`.
#[utoipa::path(
    get,
    path = "/v1/admin/restriction-definitions",
    responses(
        (status = 200, description = "Restriction definitions (admin view)", body = Vec<RestrictionDefinitionResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn admin_restriction_definitions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    match crate::handlers::restrictions::list_restriction_definitions(State(state), headers).await {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `GET /v1/admin/restriction-sets` - admin view of
/// `GET /v1/restriction-sets`.
#[utoipa::path(
    get,
    path = "/v1/admin/restriction-sets",
    responses(
        (status = 200, description = "Restriction sets (admin view)", body = Vec<RestrictionSetResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn admin_restriction_sets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::handlers::restrictions::ListRestrictionSetsQuery>,
) -> axum::response::Response {
    match crate::handlers::restrictions::list_restriction_sets(State(state), headers, Query(q))
        .await
    {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `POST /v1/admin/dlq/{id}/republish` - RFW alias of
/// `POST /v1/dlq/{id}/republish`.
#[utoipa::path(
    post,
    path = "/v1/admin/dlq/{id}/republish",
    params(("id" = uuid::Uuid, Path, description = "DLQ entry id")),
    responses(
        (status = 200, description = "Entry republished (same contract as POST /v1/dlq/{id}/republish)", body = DlqRepublishAck),
        (status = 404, description = "Unknown DLQ entry"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn admin_republish_dlq(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> axum::response::Response {
    match crate::handlers::postings::republish_dlq(State(state), headers, Path(id)).await {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `GET /v1/admin/products/{id}` - admin view of `GET /v1/products/{id}`.
#[utoipa::path(
    get,
    path = "/v1/admin/products/{id}",
    params(("id" = uuid::Uuid, Path, description = "Product id")),
    responses(
        (status = 200, description = "Product (admin view)", body = ProductResponse),
        (status = 404, description = "Unknown product"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn admin_get_product(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> axum::response::Response {
    match crate::handlers::products::get_product(State(state), headers, Path(id)).await {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `GET /v1/admin/products/{id}/versions` - admin view of
/// `GET /v1/products/{id}/versions`.
#[utoipa::path(
    get,
    path = "/v1/admin/products/{id}/versions",
    params(("id" = uuid::Uuid, Path, description = "Product id")),
    responses(
        (status = 200, description = "Product versions (admin view)", body = Vec<ProductVersionResponse>),
        (status = 404, description = "Unknown product"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn admin_list_product_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(product_id): Path<uuid::Uuid>,
) -> axum::response::Response {
    match crate::handlers::products::list_product_versions(State(state), headers, Path(product_id))
        .await
    {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `GET /v1/admin/jobs` - admin view of `GET /v1/jobs`.
#[utoipa::path(
    get,
    path = "/v1/admin/jobs",
    responses(
        (status = 200, description = "Jobs (admin view)", body = Vec<JobResponse>),
    ),
    security(),
    tag = "ledger",
)]
pub async fn admin_list_jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::handlers::schedules::ListJobsQuery>,
) -> axum::response::Response {
    match crate::handlers::schedules::list_jobs(State(state), headers, Query(q)).await {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `POST /v1/admin/products/{id}/activate` - RFW alias of
/// `POST /v1/products/{id}/activate`.
#[utoipa::path(
    post,
    path = "/v1/admin/products/{id}/activate",
    params(("id" = uuid::Uuid, Path, description = "Product id")),
    responses(
        (status = 200, description = "Product activated (same contract as POST /v1/products/{id}/activate)"),
        (status = 404, description = "Unknown product"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn admin_activate_product(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::handlers::products::activate_product(State(state), headers, Path(id)).await
}
/// `GET /v1/admin/dlq` - admin view of `GET /v1/dlq`.
#[utoipa::path(
    get,
    path = "/v1/admin/dlq",
    responses(
        (status = 200, description = "DLQ entries (admin view)", body = Vec<DlqResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn list_dlq_alias(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    match crate::handlers::postings::list_dlq(State(state), headers).await {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `GET /v1/admin/products` - admin view of `GET /v1/products`.
#[utoipa::path(
    get,
    path = "/v1/admin/products",
    responses(
        (status = 200, description = "Products (admin view)", body = Vec<ProductResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn admin_list_products(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    match crate::handlers::products::list_products(State(state), headers).await {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `GET /v1/audit` - alias of `GET /v1/admin/audit` (same handler).
#[utoipa::path(
    get,
    path = "/v1/audit",
    responses(
        (status = 200, description = "Audit events (same contract as GET /v1/admin/audit)", body = Vec<AuditEventResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn audit_events_alias(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::handlers::audit::ListAuditQuery>,
) -> axum::response::Response {
    match crate::handlers::audit::list_audit_events(State(state), headers, Query(q)).await {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}

/// `GET /v1/admin/schedules` - admin view of `GET /v1/schedules`.
#[utoipa::path(
    get,
    path = "/v1/admin/schedules",
    responses(
        (status = 200, description = "Schedules (admin view)", body = Vec<ScheduleResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the ledger scope gate"),
    ),
    security(),
    tag = "ledger",
)]
pub async fn admin_list_schedules(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::handlers::schedules::ListSchedulesQuery>,
) -> axum::response::Response {
    match crate::handlers::schedules::list_schedules(State(state), headers, Query(q)).await {
        Ok(v) => v.into_response(),
        Err((st, m)) => (st, m).into_response(),
    }
}
