// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Bank8:Ledger.
//! Output via `--print-registration` flag. See `sentin8/design/sentin8-service-self-registration-design.md`.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, ErrorCode, M2mGrant, PgRole, PolicySetDecl, Registration,
    RelationDecl, SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "bank8:ledger:read,bank8:ledger:write",
    role: "bank8_ledger_service",
    bypass_rls: false,
    // Grants live in the bank8 vertical database only (DBX §6.6
    // database-per-vertical, schema-per-service).
    database: "bank8",
    // Ledger owns all its reads - no cross-schema grants.
    cross_schema_grants: &[],
}];

/// M2M DCR scope grants (self-registration design §3.11). One entry per
/// workload this service registers via DCR; `vertical enroll` upserts
/// `certless:<workload>` rows into `sentin8.auth_m2m_scope_grants`. Scopes
/// use the full vocabulary form (bare forms + missing grants fail-closed
/// every bus/policy/stat DCR).
/// - `bank8:ledger` - the service's own client (ledger/src/server.rs):
///
/// bus produce/consume + the shared Func/Cron M2M token source.
/// - `bank8:ledger-policy` - Shield hot-reload consumer
///
/// (policy_bus_client, full colon identity).
/// - `ledger-policy` - Shield stat emitter (stat_emit short form).
/// - `ledger-audit` - shell audit-journal pusher workload (audit crate
///
/// §6.8; boot step 8c).
const M2M_GRANTS: &[M2mGrant] = &[
    M2mGrant {
        workload: "bank8:ledger",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "bank8:ledger:admin",
            "sentin8:stat:measure",
        ],
    },
    // The runtime DCR call sites pass the bare short name (`ledger`
    // ledger/src/server.rs bus client + M2M token source, and
    // telemetry.rs's stat client), not the colon identity. Grant BOTH
    // spellings; the gate looks up the exact client_name.
    M2mGrant {
        workload: "ledger",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "bank8:ledger:admin",
            "sentin8:stat:measure",
        ],
    },
    // Shell audit-journal pusher workload (audit crate §6.8; boot step 8c).
    M2mGrant {
        workload: "ledger-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    // Staff directory reads (isolation-design §10 / VDC §VDC.5): the
    // customer-search org check resolves the requested env's org via
    // Sys's tenant-snapshot API - the sanctioned on-demand cross-tenant
    // read (the former cross-database `sentin8.auth_*` / `sentin8.sys_*`
    // joins never existed in the vertical's own database).
    M2mGrant {
        workload: "bank8-ledger-sys",
        scopes: &["sentin8:sys:tenants:read"],
    },
    M2mGrant {
        workload: "bank8:ledger-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    M2mGrant {
        workload: "ledger-policy",
        scopes: &["sentin8:stat:measure"],
    },
    // Statement document uploads (schedules.rs statement generation):
    // writes the rendered statement to Sentin8:Storage under the
    // `statements` bucket (fdx statement_download.rs reads it back via a
    // signed link).
    M2mGrant {
        workload: "ledger-storage",
        scopes: &["sentin8:storage:env:write", "sentin8:storage:env:read"],
    },
    // TLS-RLS-4 (design/sentin8-vertical-data-plane-contract.md §VDC.7):
    // the database-free HostContextResolver’s resolve workload - cache
    // miss calls Sys `GET /v1/resolve/hostname`.
    M2mGrant {
        workload: "bank8-ledger-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:products:write",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:products:publish",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:products:read",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:accounts:write",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:accounts:read",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:postings:write",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:postings:read",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:schedules:write",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:schedules:read",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:jobs:read",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:jobs:admin",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:dlq:read",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:dlq:republish",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:balances:read",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:audit:read",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:customers:write",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:postings:dry_run",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:plans:read",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:plans:write",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:journal:read",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:journal:replay",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:contracts:simulate",
    },
    // Policy-admin surface (policy design §3.6; principles §6.0b per-service scope).
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:policy:read",
    },
    AdminScope::Typed {
        role: "bank8:ledger:admin",
        scope: "bank8:ledger:policy:write",
    },
];

const ERROR_CODES: &[ErrorCode] = &[
    ErrorCode {
        enum_name: "LedgerAccountNotFound",
        error_code: "ledger_account_not_found",
        status_code: 404,
    },
    ErrorCode {
        enum_name: "LedgerPostingFailed",
        error_code: "ledger_posting_failed",
        status_code: 500,
    },
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "overview",
        label: "Overview",
        ui_endpoint: "/v1/admin/ui/overview",
        data_endpoint: "/v1/admin/overview",
        icon: "0xe1b1",
    },
    AdminUiPage {
        route: "accounts",
        label: "Accounts",
        ui_endpoint: "/v1/admin/ui/accounts",
        data_endpoint: "/v1/admin/accounts",
        icon: "0xe040",
    },
    AdminUiPage {
        route: "postings",
        label: "Postings",
        ui_endpoint: "/v1/admin/ui/postings",
        data_endpoint: "/v1/admin/postings",
        icon: "0xe50d",
    },
    AdminUiPage {
        route: "products",
        label: "Products",
        ui_endpoint: "/v1/admin/ui/products",
        data_endpoint: "/v1/admin/products",
        icon: "0xe349",
    },
    AdminUiPage {
        route: "schedules",
        label: "Schedules",
        ui_endpoint: "/v1/admin/ui/schedules",
        data_endpoint: "/v1/admin/schedules",
        icon: "0xf04fb",
    },
    AdminUiPage {
        route: "jobs",
        label: "Jobs",
        ui_endpoint: "/v1/admin/ui/jobs",
        data_endpoint: "/v1/admin/jobs",
        icon: "0xe979",
    },
    AdminUiPage {
        route: "dlq",
        label: "DLQ",
        ui_endpoint: "/v1/admin/ui/dlq",
        data_endpoint: "/v1/admin/dlq",
        icon: "0xe238",
    },
    AdminUiPage {
        route: "reconcile",
        label: "Reconcile",
        ui_endpoint: "/v1/admin/ui/reconcile",
        data_endpoint: "/v1/admin/reconcile",
        icon: "0xe159",
    },
    AdminUiPage {
        route: "balances",
        label: "Balances",
        ui_endpoint: "/v1/admin/ui/balances",
        data_endpoint: "/v1/admin/balances",
        icon: "0xe083",
    },
    AdminUiPage {
        route: "parameters",
        label: "Parameters",
        ui_endpoint: "/v1/admin/ui/parameters",
        data_endpoint: "/v1/admin/parameters",
        icon: "0xe683",
    },
    AdminUiPage {
        route: "restrictions",
        label: "Restrictions",
        ui_endpoint: "/v1/admin/ui/restrictions",
        data_endpoint: "/v1/admin/restrictions",
        icon: "0xe3ae",
    },
    AdminUiPage {
        route: "flags",
        label: "Flags",
        ui_endpoint: "/v1/admin/ui/flags",
        data_endpoint: "/v1/admin/flags",
        icon: "0xe28e",
    },
    AdminUiPage {
        route: "customers",
        label: "Customers",
        ui_endpoint: "/v1/admin/ui/customers",
        data_endpoint: "/v1/admin/customers",
        icon: "0xe486",
    },
    AdminUiPage {
        route: "statements",
        label: "Statements",
        ui_endpoint: "/v1/admin/ui/statements",
        data_endpoint: "/v1/admin/statements",
        icon: "0xe1bf",
    },
    AdminUiPage {
        route: "settings",
        label: "Settings",
        ui_endpoint: "/v1/admin/ui/settings",
        data_endpoint: "/v1/admin/settings",
        icon: "0xe57f",
    },
    // Sentin8:Policy admin surface (§3.6, post pattern).
    AdminUiPage {
        route: "policy-sets",
        label: "Policy Sets",
        ui_endpoint: "/v1/admin/ui/policy-sets",
        data_endpoint: "/v1/admin/policy-sets",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "policy-decisions",
        label: "Policy Decisions",
        ui_endpoint: "/v1/admin/ui/policy-decisions",
        data_endpoint: "/v1/admin/policy-decisions",
        icon: "0xf070",
    },
    AdminUiPage {
        route: "relations",
        label: "Relations",
        ui_endpoint: "/v1/admin/ui/relations",
        data_endpoint: "/v1/admin/relations",
        icon: "0xe572",
    },
    AdminUiPage {
        route: "attributes",
        label: "Attributes",
        ui_endpoint: "/v1/admin/ui/attributes",
        data_endpoint: "/v1/admin/attributes",
        icon: "0xe8d3",
    },
];

/// Default declarative policy set (Sentin8:Policy design §3.2/§3.4,
/// seeded by `vertical enroll` as `origin='platform'`, `mode='enforced'`):
/// action-granular scope permits over the LIVE effective scope set - the
/// exact mirror of the gates this service's handlers evaluate in step 5
/// (policy design §4.3). Step 5 is the only gate; shadow is the
/// emergency one-UPDATE rollback lever only.
/// The Shield text of the declared scope-mirror set - public so the policy
/// wiring tests assert against the REAL seed (drift fails the
/// suite instead of silently diverging from enrollment).
pub const SCOPE_MIRROR_POLICIES: &str =
    "permit(principal, action == Action::\"bank8:ledger:accounts:read\", resource) when { principal.scopes.contains(\"bank8:ledger:accounts:read\") };\npermit(principal, action == Action::\"bank8:ledger:accounts:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:accounts:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:accounts:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:accounts:write\", resource) when { principal.scopes.contains(\"bank8:ledger:accounts:write\") };\npermit(principal, action == Action::\"bank8:ledger:accounts:write\", resource) when { principal.scopes.contains(\"bank8:ledger:customers:write\") };\npermit(principal, action == Action::\"bank8:ledger:accounts:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:accounts:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:accounts:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:audit:read\", resource) when { principal.scopes.contains(\"bank8:ledger:audit:read\") };\npermit(principal, action == Action::\"bank8:ledger:audit:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:audit:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:audit:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:balances:read\", resource) when { principal.scopes.contains(\"bank8:ledger:accounts:read\") };\npermit(principal, action == Action::\"bank8:ledger:balances:read\", resource) when { principal.scopes.contains(\"bank8:ledger:balances:read\") };\npermit(principal, action == Action::\"bank8:ledger:balances:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:balances:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:balances:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:customers:write\", resource) when { principal.scopes.contains(\"bank8:ledger:customers:write\") };\npermit(principal, action == Action::\"bank8:ledger:customers:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:customers:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:customers:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:dlq:read\", resource) when { principal.scopes.contains(\"bank8:ledger:dlq:read\") };\npermit(principal, action == Action::\"bank8:ledger:dlq:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:dlq:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:dlq:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:dlq:republish\", resource) when { principal.scopes.contains(\"bank8:ledger:dlq:republish\") };\npermit(principal, action == Action::\"bank8:ledger:dlq:republish\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:dlq:republish\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:dlq:republish\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:jobs:admin\", resource) when { principal.scopes.contains(\"bank8:ledger:jobs:admin\") };\npermit(principal, action == Action::\"bank8:ledger:jobs:admin\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:jobs:admin\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:jobs:admin\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:jobs:read\", resource) when { principal.scopes.contains(\"bank8:ledger:jobs:read\") };\npermit(principal, action == Action::\"bank8:ledger:jobs:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:jobs:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:jobs:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:postings:read\", resource) when { principal.scopes.contains(\"bank8:ledger:audit:read\") };\npermit(principal, action == Action::\"bank8:ledger:postings:read\", resource) when { principal.scopes.contains(\"bank8:ledger:dlq:read\") };\npermit(principal, action == Action::\"bank8:ledger:postings:read\", resource) when { principal.scopes.contains(\"bank8:ledger:postings:read\") };\npermit(principal, action == Action::\"bank8:ledger:postings:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:postings:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:postings:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:postings:write\", resource) when { principal.scopes.contains(\"bank8:ledger:dlq:republish\") };\npermit(principal, action == Action::\"bank8:ledger:postings:write\", resource) when { principal.scopes.contains(\"bank8:ledger:jobs:admin\") };\npermit(principal, action == Action::\"bank8:ledger:postings:write\", resource) when { principal.scopes.contains(\"bank8:ledger:postings:write\") };\npermit(principal, action == Action::\"bank8:ledger:postings:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:postings:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:postings:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:products:publish\", resource) when { principal.scopes.contains(\"bank8:ledger:products:publish\") };\npermit(principal, action == Action::\"bank8:ledger:products:publish\", resource) when { principal.scopes.contains(\"bank8:ledger:products:write\") };\npermit(principal, action == Action::\"bank8:ledger:products:publish\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:products:publish\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:products:publish\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:products:read\", resource) when { principal.scopes.contains(\"bank8:ledger:products:read\") };\npermit(principal, action == Action::\"bank8:ledger:products:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:products:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:products:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:products:write\", resource) when { principal.scopes.contains(\"bank8:ledger:products:write\") };\npermit(principal, action == Action::\"bank8:ledger:products:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:products:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:products:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:schedules:read\", resource) when { principal.scopes.contains(\"bank8:ledger:schedules:read\") };\npermit(principal, action == Action::\"bank8:ledger:schedules:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:schedules:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:schedules:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:ledger:schedules:write\", resource) when { principal.scopes.contains(\"bank8:ledger:schedules:write\") };\npermit(principal, action == Action::\"bank8:ledger:schedules:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:ledger:schedules:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:ledger:schedules:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };";

/// (single-line mirror text - see the POLICIES decl below for the
/// description/mode wiring)
const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
    policy_set_name: "scope-mirror",
    description: "Action-granular scope permits for bank8:ledger over the LIVE effective scope set (design §3.1d). Step 5 is the only gate.",
    // Shield text lives in SCOPE_MIRROR_POLICIES (single source; the policy
    // wiring tests assert against this exact string - drift fails the suite).
    policies: SCOPE_MIRROR_POLICIES,
    schema: None,
    mode: "enforced",
    default_enabled: true,
}];

/// Default ReBAC relation tuples (design §3.1c) - none declared by ledger
/// today; env admins author their own graph via the relations admin API.
const RELATIONS: &[RelationDecl] = &[];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::LedgerOpenApi::openapi())
        .unwrap_or(serde_json::Value::Null)
}

/// Print the registration JSON to stdout.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "bank8:ledger",
        subdomain: "bank8-ledger",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: ERROR_CODES,
        consent_providers: &[],
        consent_flows: &[],
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
        admin_ui: Some(AdminUi {
            label: "Ledger",
            icon: "0xe040",
            service_flag: "ledger",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_1_INIT,
        }],
        pg_roles: PG_ROLES,
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
