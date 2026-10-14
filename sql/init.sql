-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
-- SPDX-License-Identifier: Apache-2.0

-- Bank8:Ledger — the service's own schema `ledger` (schema-per-service):
-- ledger_* domain tables + ledger.outbox / ledger.audit_journal producer
-- tables, all FORCE-RLS env-scoped.
--
-- The Bank8:Ledger-owned ledger.product_versions (WASM binary registry for Bank8:Ledger
-- product versions) and ledger.account_flags (set_flag directive) are defined
-- below — they are Bank8:Ledger concepts that reference ledger.products and
-- ledger.accounts, so they must live here (after those tables are created).

-- Bank8:Ledger accounts table
CREATE SCHEMA IF NOT EXISTS ledger;
CREATE TABLE IF NOT EXISTS ledger.accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    customer_id     UUID,
    product_id      UUID,
    account_type    TEXT NOT NULL CHECK (account_type IN ('customer', 'internal')),
    product_type    TEXT,
    nickname        TEXT,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'closed', 'frozen')),
    denomination    TEXT NOT NULL DEFAULT 'CAD',
    opened_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resource_version INTEGER NOT NULL DEFAULT 1,
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_ledger_accounts_env ON ledger.accounts (env_id);
CREATE INDEX IF NOT EXISTS idx_ledger_accounts_customer ON ledger.accounts (customer_id) WHERE deleted_at IS NULL;

-- Bank8:Ledger products table
CREATE TABLE IF NOT EXISTS ledger.products (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    product_type    TEXT NOT NULL,
    name            TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('draft', 'active', 'deprecated')),
    parameters      JSONB NOT NULL DEFAULT '{}',
    modules         JSONB NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resource_version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_ledger_products_env ON ledger.products (env_id);

-- Bank8:Ledger postings table — posting instruction batches
CREATE TABLE IF NOT EXISTS ledger.postings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    batch_id        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected', 'processing')),
    idempotency_key TEXT,
    instruction_count INTEGER NOT NULL DEFAULT 0,
    correlation_id  TEXT,
    created_by       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    resource_version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_ledger_postings_env ON ledger.postings (env_id);
-- Idempotency: a partial UNIQUE index closes the SELECT-then-INSERT race —
-- concurrent batches with the same key collide on insert and the ON CONFLICT
-- clause returns the original row (posting engine §4.1).
CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_postings_idempotency
    ON ledger.postings (env_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

-- Bank8:Ledger posting instructions (individual debits/credits within a batch)
CREATE TABLE IF NOT EXISTS ledger.posting_instructions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    posting_id      UUID NOT NULL REFERENCES ledger.postings(id),
    instruction_type TEXT NOT NULL,
    debit_account   UUID NOT NULL,
    credit_account  UUID NOT NULL,
    amount          DECIMAL(20,2) NOT NULL,
    denomination    TEXT NOT NULL DEFAULT 'CAD',
    value_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    status          TEXT NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ledger_posting_instructions_posting ON ledger.posting_instructions (posting_id);

-- Bank8:Ledger balances table (materialized view of current balances)
CREATE TABLE IF NOT EXISTS ledger.balances (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    account_id      UUID NOT NULL,
    denomination    TEXT NOT NULL DEFAULT 'CAD',
    address         TEXT NOT NULL DEFAULT 'DEFAULT',
    phase           TEXT NOT NULL DEFAULT 'COMMITTED',
    amount          DECIMAL(20,2) NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (account_id, denomination, address, phase)
);

CREATE INDEX IF NOT EXISTS idx_ledger_balances_account ON ledger.balances (account_id);

-- Bank8:Ledger schedules table
CREATE TABLE IF NOT EXISTS ledger.schedules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    account_id      UUID,
    schedule_type   TEXT NOT NULL,
    cron_expression TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    last_run_at     TIMESTAMPTZ,
    next_run_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Bank8:Ledger jobs table
CREATE TABLE IF NOT EXISTS ledger.jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    schedule_id     UUID,
    job_type        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'overridden')),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Bank8:Ledger DLQ table
CREATE TABLE IF NOT EXISTS ledger.dlq (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    message_type    TEXT NOT NULL,
    payload         JSONB NOT NULL,
    error_message   TEXT NOT NULL,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Bank8:Ledger audit events
CREATE TABLE IF NOT EXISTS ledger.audit_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    actor_user_id       TEXT,
    action              TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id  TEXT,
    correlation_id      TEXT,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT now(),
    schema_version      TEXT NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS idx_ledger_audit_env ON ledger.audit_events (env_id);

-- ──────────────────────────────────────────────────────────────────────────
-- Bank8:Ledger extended tables — flags, restrictions, parameters, customers,
-- product version configs, calendars, transactions, statements, account
-- schedule associations.
-- Stories 10.1.22–10.1.43.

-- Bank8:Ledger customers table
CREATE TABLE IF NOT EXISTS ledger.customers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    -- Party type (F8 institution scout): 'person' = a human customer
    -- (optionally linked to a Sentin8:Auth user); 'institution' = the bank
    -- itself in this env (one per env, created by seed_internal_accounts —
    -- owns the internal chart-of-accounts so customer_id is never NULL).
    -- The institution row NEVER links an auth user (sentin8_auth_user_id
    -- stays NULL) so the §4.3c holder subquery can never match it — it is
    -- structurally invisible to customers. account_type remains the
    -- enforcement discriminator; customer_type is modeling + audit.
    customer_type   TEXT NOT NULL DEFAULT 'person' CHECK (customer_type IN ('person', 'institution')),
    -- Sentin8:Auth user link (Epic 15.6). Nullable — customers often exist before
    -- they sign up (in-branch onboarding, KYC import). Stamped by Bank8:Ledger
    -- `POST /v1/customers/{id}/link-auth` when the customer completes Sentin8:Auth
    -- sign-up. Used by holder-scoped RLS (§4.3c) to admit customer-realm
    -- callers. Unique within (env_id) so two customers in the same
    -- env can't claim the same Sentin8:Auth user.
    sentin8_auth_user_id   UUID,
    display_name    TEXT NOT NULL,
    email           TEXT,
    phone           TEXT,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'deceased')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resource_version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_ledger_customers_env ON ledger.customers (env_id);
CREATE INDEX IF NOT EXISTS idx_ledger_customers_sentin8_auth_user ON ledger.customers (sentin8_auth_user_id) WHERE sentin8_auth_user_id IS NOT NULL;
-- Partial unique index: only non-NULL sentin8_auth_user_id enforces uniqueness within
-- (env_id). NULL rows (pre-auth customers) are exempt — multiple
-- customers can have sentin8_auth_user_id IS NULL in the same env.
CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_customers_sentin8_auth_user_uniq
    ON ledger.customers (env_id, sentin8_auth_user_id)
    WHERE sentin8_auth_user_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_customers_sentin8_auth_user_uniq
    ON ledger.customers (env_id, sentin8_auth_user_id)
    WHERE sentin8_auth_user_id IS NOT NULL;

-- F8 institution scout: exactly ONE institution party per env (the bank
-- itself). Partial unique index — only rows with customer_type='institution'
-- participate, so any number of person customers remain allowed.
CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_customers_institution_uniq
    ON ledger.customers (env_id)
    WHERE customer_type = 'institution';

-- Bank8:Ledger flag definitions
CREATE TABLE IF NOT EXISTS ledger.flag_definitions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    flag_name       TEXT NOT NULL,
    required_flag_level TEXT NOT NULL DEFAULT 'ACCOUNT' CHECK (required_flag_level IN ('CUSTOMER', 'ACCOUNT')),
    flag_visibility TEXT NOT NULL DEFAULT 'PRIVATE',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, flag_name)
);
CREATE INDEX IF NOT EXISTS idx_ledger_flag_definitions_env ON ledger.flag_definitions (env_id);

-- Bank8:Ledger flags (account or customer level)
CREATE TABLE IF NOT EXISTS ledger.flags (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    flag_definition_id UUID NOT NULL REFERENCES ledger.flag_definitions(id),
    account_id      UUID REFERENCES ledger.accounts(id),
    customer_id     UUID REFERENCES ledger.customers(id),
    value           TEXT NOT NULL DEFAULT 'ON' CHECK (value IN ('ON', 'OFF')),
    effective_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    expiry_timestamp    TIMESTAMPTZ,
    is_backdated    BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (account_id IS NOT NULL OR customer_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_ledger_flags_account ON ledger.flags (account_id) WHERE account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ledger_flags_customer ON ledger.flags (customer_id) WHERE customer_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ledger_flags_definition ON ledger.flags (flag_definition_id);

-- Bank8:Ledger restriction definitions
CREATE TABLE IF NOT EXISTS ledger.restriction_definitions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    action          TEXT NOT NULL CHECK (action IN ('PREVENT_DEBIT', 'PREVENT_CREDIT', 'PREVENT_CLOSURE', 'PREVENT_ACCOUNT_UPDATE', 'PREVENT_ACCOUNT_CONVERSION')),
    description     TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ledger_restriction_defs_env ON ledger.restriction_definitions (env_id);

-- Bank8:Ledger restriction sets (applied to accounts or customers)
CREATE TABLE IF NOT EXISTS ledger.restriction_sets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    restriction_definition_id UUID NOT NULL REFERENCES ledger.restriction_definitions(id),
    account_id      UUID REFERENCES ledger.accounts(id),
    customer_id     UUID REFERENCES ledger.customers(id),
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'overridden')),
    effective_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    expiry_timestamp    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (account_id IS NOT NULL OR customer_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_ledger_restriction_sets_account ON ledger.restriction_sets (account_id) WHERE account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ledger_restriction_sets_customer ON ledger.restriction_sets (customer_id) WHERE customer_id IS NOT NULL;

-- Bank8:Ledger parameters (template/instance/derived definitions)
CREATE TABLE IF NOT EXISTS ledger.parameters (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    is_instance     BOOLEAN NOT NULL DEFAULT false,
    is_template     BOOLEAN NOT NULL DEFAULT true,
    is_derived      BOOLEAN NOT NULL DEFAULT false,
    data_type       TEXT NOT NULL DEFAULT 'string',
    constraints     JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);
CREATE INDEX IF NOT EXISTS idx_ledger_parameters_env ON ledger.parameters (env_id);

-- Bank8:Ledger parameter values (hierarchical: account > hierarchy node > global)
CREATE TABLE IF NOT EXISTS ledger.parameter_values (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    parameter_id    UUID NOT NULL REFERENCES ledger.parameters(id),
    account_id      UUID REFERENCES ledger.accounts(id),
    hierarchy_node_id UUID,
    is_global       BOOLEAN NOT NULL DEFAULT false,
    value           JSONB NOT NULL,
    effective_from_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    effective_to_timestamp   TIMESTAMPTZ,
    is_backdated    BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ledger_param_values_param ON ledger.parameter_values (parameter_id);
CREATE INDEX IF NOT EXISTS idx_ledger_param_values_account ON ledger.parameter_values (account_id) WHERE account_id IS NOT NULL;

-- Bank8:Ledger parameter value hierarchy nodes (tree up to 7 layers)
CREATE TABLE IF NOT EXISTS ledger.parameter_value_hierarchy_nodes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    parent_id       UUID REFERENCES ledger.parameter_value_hierarchy_nodes(id),
    name            TEXT NOT NULL,
    layer           INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ledger_hierarchy_nodes_env ON ledger.parameter_value_hierarchy_nodes (env_id);
CREATE INDEX IF NOT EXISTS idx_ledger_hierarchy_nodes_parent ON ledger.parameter_value_hierarchy_nodes (parent_id) WHERE parent_id IS NOT NULL;

-- Bank8:Ledger product versions (extends ledger.products with versioned configurations)
CREATE TABLE IF NOT EXISTS ledger.product_versions_ext (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    product_id      UUID NOT NULL REFERENCES ledger.products(id),
    version_number  INTEGER NOT NULL,
    tside           TEXT NOT NULL DEFAULT 'LIABILITY' CHECK (tside IN ('UNKNOWN', 'ASSET', 'LIABILITY')),
    create_account_template JSONB NOT NULL DEFAULT '{}',
    contract_modules JSONB NOT NULL DEFAULT '[]',
    supported_denominations TEXT[] NOT NULL DEFAULT '{}',
    parameters      JSONB NOT NULL DEFAULT '{}',
    expected_parameters JSONB NOT NULL DEFAULT '[]',
    adjustments_versioning_policy TEXT NOT NULL DEFAULT 'LATEST' CHECK (adjustments_versioning_policy IN ('HISTORIC', 'LATEST')),
    status          TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'deprecated')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (product_id, version_number)
);
CREATE INDEX IF NOT EXISTS idx_ledger_product_versions_ext_product ON ledger.product_versions_ext (product_id);

-- ──────────────────────────────────────────────────────────────────────────
-- Bank8:Ledger product versions (WASM binary metadata for Bank8:Ledger product versions).
-- Each product version contains a compiled WASM binary, the source language,
-- declared hooks, and parameter schemas. The WASM binary is executed by Sentin8:Func,
-- but the metadata is a Bank8:Ledger concept (it references ledger.products).
CREATE TABLE IF NOT EXISTS ledger.product_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    product_id      UUID NOT NULL REFERENCES ledger.products(id),
    version_label   TEXT NOT NULL,
    wasm_hash       TEXT NOT NULL,              -- sha256:hex…
    wasm_size       INTEGER NOT NULL,          -- bytes
    wasm_language   TEXT NOT NULL CHECK (wasm_language IN ('typescript', 'rust')),
    hooks           TEXT[] NOT NULL DEFAULT '{}',  -- ["pre_posting","post_posting",…]
    parameters      JSONB NOT NULL DEFAULT '{}',   -- { template: {...}, instance: {...} }
    description     TEXT,
    status          TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'deprecated')),
    uploaded_by     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resource_version INTEGER NOT NULL DEFAULT 1,
    UNIQUE (product_id, version_label)
);

CREATE INDEX IF NOT EXISTS idx_ledger_product_versions_env ON ledger.product_versions (env_id);
CREATE INDEX IF NOT EXISTS idx_ledger_product_versions_product ON ledger.product_versions (product_id);
CREATE INDEX IF NOT EXISTS idx_ledger_product_versions_active ON ledger.product_versions (product_id) WHERE status = 'active';

-- Bank8:Ledger account flags table — used by Sentin8:Func set_flag directive
CREATE TABLE IF NOT EXISTS ledger.account_flags (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    account_id      UUID NOT NULL REFERENCES ledger.accounts(id),
    flag_name       TEXT NOT NULL,
    flag_value      BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (account_id, flag_name)
);

CREATE INDEX IF NOT EXISTS idx_ledger_account_flags_account ON ledger.account_flags (account_id);

-- Bank8:Ledger calendars (EOD processing schedules)
CREATE TABLE IF NOT EXISTS ledger.calendars (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    timezone        TEXT NOT NULL DEFAULT 'UTC',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);

-- Bank8:Ledger transactions (derived from postings for account history)
CREATE TABLE IF NOT EXISTS ledger.transactions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    account_id      UUID NOT NULL REFERENCES ledger.accounts(id),
    posting_id      UUID NOT NULL REFERENCES ledger.postings(id),
    instruction_id  UUID REFERENCES ledger.posting_instructions(id),
    amount          DECIMAL(28,10) NOT NULL,
    denomination    TEXT NOT NULL DEFAULT 'CAD',
    direction       TEXT NOT NULL CHECK (direction IN ('debit', 'credit')),
    description     TEXT,
    value_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    booking_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ledger_transactions_account ON ledger.transactions (account_id, value_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_transactions_posting ON ledger.transactions (posting_id);

-- Bank8:Ledger statements (generated monthly, stored in Sentin8:Buck)
CREATE TABLE IF NOT EXISTS ledger.statements (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    account_id      UUID NOT NULL REFERENCES ledger.accounts(id),
    period_start    TIMESTAMPTZ NOT NULL,
    period_end      TIMESTAMPTZ NOT NULL,
    opening_balance DECIMAL(28,10) NOT NULL DEFAULT 0,
    closing_balance DECIMAL(28,10) NOT NULL DEFAULT 0,
    document_url    TEXT,
    document_format TEXT NOT NULL DEFAULT 'pdf' CHECK (document_format IN ('pdf', 'html')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ledger_statements_account ON ledger.statements (account_id, period_start DESC);

-- Bank8:Ledger account schedule associations (account ↔ schedule join)
CREATE TABLE IF NOT EXISTS ledger.account_schedule_assocs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    account_id      UUID NOT NULL REFERENCES ledger.accounts(id),
    schedule_id     UUID NOT NULL REFERENCES ledger.schedules(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (account_id, schedule_id)
);
CREATE INDEX IF NOT EXISTS idx_ledger_account_schedule_assocs_account ON ledger.account_schedule_assocs (account_id);

-- ── LEDG-COMPLETE epic (2026-09-06) — new tables for the business API
-- completion (design §8.0). All env-scoped, RLS-enabled, no migration
-- code (new platform — re-seed via `vertical init`).

-- Journal events (LC-2): append-only hash-chained journal. INSERT-only
-- at the SQL level — no UPDATE/DELETE policy is created (append-only).
CREATE TABLE IF NOT EXISTS ledger.journal_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     UUID NOT NULL,
    operation       TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_checksum   TEXT,
    checksum        TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ledger_journal_events_resource
    ON ledger.journal_events (env_id, resource_type, resource_id, created_at DESC);

-- Adjustments (LC-3): retroactive recomputation of account state.
CREATE TABLE IF NOT EXISTS ledger.adjustments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id              UUID NOT NULL,
    account_id          UUID NOT NULL REFERENCES ledger.accounts(id),
    reason              TEXT NOT NULL,
    effective_date      TIMESTAMPTZ NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','failed')),
    correction_batch_id UUID REFERENCES ledger.postings(id),
    error_message       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ledger_adjustments_account
    ON ledger.adjustments (env_id, account_id, created_at DESC);

-- Plans (LC-8): bundled product terms across accounts.
CREATE TABLE IF NOT EXISTS ledger.plans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    name            TEXT NOT NULL,
    product_type    TEXT,
    parameters      JSONB NOT NULL DEFAULT '{}'::jsonb,
    modules         JSONB NOT NULL DEFAULT '[]'::jsonb,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','open','closed')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);
CREATE TABLE IF NOT EXISTS ledger.plan_assocs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    plan_id         UUID NOT NULL REFERENCES ledger.plans(id),
    account_id      UUID NOT NULL REFERENCES ledger.accounts(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (plan_id, account_id)
);
CREATE TABLE IF NOT EXISTS ledger.plan_migrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    plan_id         UUID NOT NULL REFERENCES ledger.plans(id),
    from_plan_id    UUID REFERENCES ledger.plans(id),
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed','failed')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Processing groups (LC-5): timezone-offset EOD batching (Cron is UTC-only,
-- cron design §4.2a — offsets are ledger-side).
CREATE TABLE IF NOT EXISTS ledger.processing_groups (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id                  UUID NOT NULL,
    name                    TEXT NOT NULL,
    utc_offset              TEXT NOT NULL DEFAULT 'UTC',
    eod_cut_off             TEXT NOT NULL DEFAULT '18:00',
    grace_period_minutes    INTEGER NOT NULL DEFAULT 0,
    paused                  BOOLEAN NOT NULL DEFAULT false,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);

-- Calendar model completion (LC-6): events, periods, bookkeeping dates.
CREATE TABLE IF NOT EXISTS ledger.calendar_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    calendar_id     UUID NOT NULL REFERENCES ledger.calendars(id),
    event_date      DATE NOT NULL,
    event_type      TEXT NOT NULL CHECK (event_type IN ('HOLIDAY','WEEKEND','ROLL','PAUSE')),
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (calendar_id, event_date, event_type)
);
CREATE TABLE IF NOT EXISTS ledger.calendar_periods (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    calendar_id     UUID NOT NULL REFERENCES ledger.calendars(id),
    start_date      DATE NOT NULL,
    end_date        DATE NOT NULL,
    period_type     TEXT NOT NULL DEFAULT 'monthly',
    descriptor      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ledger.bookkeeping_dates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    calendar_id     UUID NOT NULL REFERENCES ledger.calendars(id),
    effective_date  DATE NOT NULL,
    bookkeeping_date DATE NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (calendar_id, effective_date)
);

-- Schedule tags (LC-7): activation control for schedules.
CREATE TABLE IF NOT EXISTS ledger.schedule_tags (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    name            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);
CREATE TABLE IF NOT EXISTS ledger.schedule_tag_assocs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    tag_id          UUID NOT NULL REFERENCES ledger.schedule_tags(id),
    schedule_id     UUID NOT NULL REFERENCES ledger.schedules(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tag_id, schedule_id)
);
CREATE TABLE IF NOT EXISTS ledger.account_schedule_tags (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    account_id      UUID NOT NULL REFERENCES ledger.accounts(id),
    tag_id          UUID NOT NULL REFERENCES ledger.schedule_tags(id),
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (account_id, tag_id)
);

-- Payment devices (LC-13): card/device tokens attached to accounts.
CREATE TABLE IF NOT EXISTS ledger.payment_devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    account_id      UUID NOT NULL REFERENCES ledger.accounts(id),
    device_type     TEXT NOT NULL DEFAULT 'card',
    device_token_ref TEXT NOT NULL,          -- secret reference, never raw PAN
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ledger_payment_devices_account
    ON ledger.payment_devices (env_id, account_id);

-- Account attributes (LC-13): per-account attribute values.
CREATE TABLE IF NOT EXISTS ledger.account_attributes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    account_id      UUID NOT NULL REFERENCES ledger.accounts(id),
    attribute_key   TEXT NOT NULL,
    value           JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (account_id, attribute_key)
);

-- Global parameters (LC-11): env-wide parameter hierarchy.
-- Resolution order: global → product → account (instance).
CREATE TABLE IF NOT EXISTS ledger.global_parameters (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    name            TEXT NOT NULL,
    shape           JSONB NOT NULL DEFAULT '{}'::jsonb,
    value           JSONB NOT NULL DEFAULT 'null'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);

-- Supervisor contracts (LC-9): cross-account contracts (sweeps, rebalancing).
CREATE TABLE IF NOT EXISTS ledger.supervisor_contracts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    name            TEXT NOT NULL,
    func_module_id  TEXT NOT NULL,           -- Sentin8:Func module (hook logic)
    member_account_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    parameters      JSONB NOT NULL DEFAULT '{}'::jsonb,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);

-- Bulk batches (LC-15): account migrations + bulk account updates
-- (Sentin8 Jobs bulk-operations pattern).
CREATE TABLE IF NOT EXISTS ledger.account_migrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    source_system   TEXT,
    payload         JSONB NOT NULL DEFAULT '[]'::jsonb,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed','failed')),
    item_count      INTEGER NOT NULL DEFAULT 0,
    failed_count    INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ledger.account_update_batches (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    payload         JSONB NOT NULL DEFAULT '[]'::jsonb,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed','failed')),
    item_count      INTEGER NOT NULL DEFAULT 0,
    failed_item_count INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Enable RLS on ALL tenant data tables (architecture-principles.md §4.3).
ALTER TABLE ledger.accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.accounts FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.products ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.products FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.postings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.postings FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.posting_instructions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.posting_instructions FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.balances ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.balances FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.schedules FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.dlq ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.dlq FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.customers FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.flag_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.flag_definitions FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.flags FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.restriction_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.restriction_definitions FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.restriction_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.restriction_sets FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.parameters ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.parameters FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.parameter_values ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.parameter_values FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.parameter_value_hierarchy_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.parameter_value_hierarchy_nodes FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.product_versions_ext ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.product_versions_ext FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.product_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.product_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.account_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.account_flags FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.calendars ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.calendars FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.transactions FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.statements ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.statements FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.account_schedule_assocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.account_schedule_assocs FORCE ROW LEVEL SECURITY;

-- LEDG-COMPLETE epic: RLS on the new tables (design §8.0).
ALTER TABLE ledger.journal_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.journal_events FORCE ROW LEVEL SECURITY;
-- Append-only: SELECT + INSERT policies only (no UPDATE/DELETE policy exists —
-- the journal is immutable; replay appends new rows, never rewrites).
DROP POLICY IF EXISTS journal_events_select ON ledger.journal_events;
CREATE POLICY journal_events_select ON ledger.journal_events FOR SELECT USING (
            sentin8_context_initialized()
            AND env_id = sentin8_current_env_id()
        );
DROP POLICY IF EXISTS journal_events_insert ON ledger.journal_events;
CREATE POLICY journal_events_insert ON ledger.journal_events FOR INSERT WITH CHECK (
            sentin8_context_initialized()
            AND env_id = sentin8_current_env_id()
        );
ALTER TABLE ledger.adjustments ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.adjustments FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.plans FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.plan_assocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.plan_assocs FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.plan_migrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.plan_migrations FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.processing_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.processing_groups FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.calendar_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.calendar_events FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.calendar_periods ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.calendar_periods FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.bookkeeping_dates ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.bookkeeping_dates FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.schedule_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.schedule_tags FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.schedule_tag_assocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.schedule_tag_assocs FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.account_schedule_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.account_schedule_tags FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.payment_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.payment_devices FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.account_attributes ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.account_attributes FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.global_parameters ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.global_parameters FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.supervisor_contracts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.supervisor_contracts FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.account_migrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.account_migrations FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.account_update_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.account_update_batches FORCE ROW LEVEL SECURITY;

-- RLS policies (standard env pattern) — applied to ALL tenant tables.
DO $$
DECLARE
    tbl TEXT;
    tables TEXT[] := ARRAY[
        'ledger.accounts', 'ledger.products',
        'ledger.postings', 'ledger.posting_instructions',
        'ledger.balances', 'ledger.schedules',
        'ledger.jobs', 'ledger.dlq',
        'ledger.audit_events',
        'ledger.customers', 'ledger.flag_definitions',
        'ledger.flags', 'ledger.restriction_definitions',
        'ledger.restriction_sets',
        'ledger.parameters', 'ledger.parameter_values',
        'ledger.parameter_value_hierarchy_nodes', 'ledger.product_versions_ext',
        'ledger.product_versions', 'ledger.account_flags',
        'ledger.calendars', 'ledger.transactions', 'ledger.statements',
        'ledger.account_schedule_assocs',
        'ledger.adjustments', 'ledger.plans',
        'ledger.plan_assocs', 'ledger.plan_migrations',
        'ledger.processing_groups', 'ledger.calendar_events',
        'ledger.calendar_periods', 'ledger.bookkeeping_dates',
        'ledger.schedule_tags', 'ledger.schedule_tag_assocs',
        'ledger.account_schedule_tags', 'ledger.payment_devices',
        'ledger.account_attributes', 'ledger.global_parameters',
        'ledger.supervisor_contracts', 'ledger.account_migrations',
        'ledger.account_update_batches'
    ];
BEGIN
    FOREACH tbl IN ARRAY tables LOOP
        EXECUTE format('DROP POLICY IF EXISTS %1$I_select ON %2$s;
CREATE POLICY %1$I_select ON %2$s FOR SELECT USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', split_part(tbl, '.', 2), tbl);
        EXECUTE format('DROP POLICY IF EXISTS %1$I_insert ON %2$s;
CREATE POLICY %1$I_insert ON %2$s FOR INSERT WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', split_part(tbl, '.', 2), tbl);
        EXECUTE format('DROP POLICY IF EXISTS %1$I_update ON %2$s;
CREATE POLICY %1$I_update ON %2$s FOR UPDATE USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', split_part(tbl, '.', 2), tbl);
        EXECUTE format('DROP POLICY IF EXISTS %1$I_delete ON %2$s;
CREATE POLICY %1$I_delete ON %2$s FOR DELETE USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', split_part(tbl, '.', 2), tbl);
    END LOOP;
END $$;

-- Enable + FORCE RLS on tables in the loop that were missing it
ALTER TABLE ledger.product_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.product_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger.account_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.account_flags FORCE ROW LEVEL SECURITY;

-- Enable + FORCE RLS on tables with env_id that were missing RLS entirely
ALTER TABLE ledger.postings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.postings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS postings_select ON ledger.postings;
CREATE POLICY postings_select ON ledger.postings FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS postings_insert ON ledger.postings;
CREATE POLICY postings_insert ON ledger.postings FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS postings_update ON ledger.postings;
CREATE POLICY postings_update ON ledger.postings FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS postings_delete ON ledger.postings;
CREATE POLICY postings_delete ON ledger.postings FOR DELETE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE ledger.posting_instructions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.posting_instructions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS posting_instructions_select ON ledger.posting_instructions;
CREATE POLICY posting_instructions_select ON ledger.posting_instructions FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS posting_instructions_insert ON ledger.posting_instructions;
CREATE POLICY posting_instructions_insert ON ledger.posting_instructions FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS posting_instructions_update ON ledger.posting_instructions;
CREATE POLICY posting_instructions_update ON ledger.posting_instructions FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS posting_instructions_delete ON ledger.posting_instructions;
CREATE POLICY posting_instructions_delete ON ledger.posting_instructions FOR DELETE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE ledger.balances ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.balances FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS balances_select ON ledger.balances;
CREATE POLICY balances_select ON ledger.balances FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE ledger.schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.schedules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS schedules_select ON ledger.schedules;
CREATE POLICY schedules_select ON ledger.schedules FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS schedules_insert ON ledger.schedules;
CREATE POLICY schedules_insert ON ledger.schedules FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS schedules_update ON ledger.schedules;
CREATE POLICY schedules_update ON ledger.schedules FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS schedules_delete ON ledger.schedules;
CREATE POLICY schedules_delete ON ledger.schedules FOR DELETE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE ledger.jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jobs_select ON ledger.jobs;
CREATE POLICY jobs_select ON ledger.jobs FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS jobs_insert ON ledger.jobs;
CREATE POLICY jobs_insert ON ledger.jobs FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS jobs_update ON ledger.jobs;
CREATE POLICY jobs_update ON ledger.jobs FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS jobs_delete ON ledger.jobs;
CREATE POLICY jobs_delete ON ledger.jobs FOR DELETE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE ledger.dlq ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.dlq FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS dlq_select ON ledger.dlq;
CREATE POLICY dlq_select ON ledger.dlq FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS dlq_insert ON ledger.dlq;
CREATE POLICY dlq_insert ON ledger.dlq FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS dlq_update ON ledger.dlq;
CREATE POLICY dlq_update ON ledger.dlq FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS dlq_delete ON ledger.dlq;
CREATE POLICY dlq_delete ON ledger.dlq FOR DELETE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE ledger.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_events_select ON ledger.audit_events;
CREATE POLICY audit_events_select ON ledger.audit_events FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS audit_events_insert ON ledger.audit_events;
CREATE POLICY audit_events_insert ON ledger.audit_events FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- Holder-scoped RLS policies (§4.3c — customer-held records; Option A revision).
-- ledger.accounts, ledger.flags, ledger.restriction_sets carry customer_id.
-- ALL human callers (customers AND staff) see only rows held by a customer linked to
-- their Sentin8:Auth user. `holder:view-all` is M2M-ONLY (architecture-principles
-- §4.3c revision, §4.3f): the branch is gated on token_tp = 'm2m' so a leaked
-- user-role grant cannot activate env-wide visibility. Staff access to customer
-- data goes through CIBA delegation — which mints a normal customer token.
-- These DROP + REPLACE the standard env policies created by the loop above.
ALTER TABLE ledger.accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.accounts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS accounts_select ON ledger.accounts;
CREATE POLICY accounts_select ON ledger.accounts FOR SELECT USING (
            sentin8_context_initialized()
            AND (
                (sentin8_has_scope('holder:view-all') = FALSE
                    AND env_id = sentin8_current_env_id()
                    AND customer_id IN (
                      SELECT id FROM ledger.customers
                      WHERE sentin8_auth_user_id = sentin8_current_sentin8_auth_user_id()
                    ))
                OR (sentin8_has_scope('holder:view-all')
                    AND sentin8_current_token_tp() = 'm2m'
                    AND env_id = sentin8_current_env_id())
                -- Staff-override branch (isolation-design §10.1): the
                -- handler validated the caller's org relationship and
                -- stamped the request — counterparty plumbing (internal
                -- accounts) in the overridden env is readable for this
                -- transaction only. Never exposes customer rows.
                OR (current_setting('app.staff_override', TRUE) = 'true'
                    AND env_id = sentin8_current_env_id())
            )
        );
DROP POLICY IF EXISTS accounts_insert ON ledger.accounts;
CREATE POLICY accounts_insert ON ledger.accounts FOR INSERT WITH CHECK (
            sentin8_context_initialized()
            AND env_id = sentin8_current_env_id()
        );
DROP POLICY IF EXISTS accounts_update ON ledger.accounts;
CREATE POLICY accounts_update ON ledger.accounts FOR UPDATE USING (
            sentin8_context_initialized()
            AND env_id = sentin8_current_env_id()
        );
DROP POLICY IF EXISTS accounts_delete ON ledger.accounts;
CREATE POLICY accounts_delete ON ledger.accounts FOR DELETE USING (
            sentin8_context_initialized()
            AND env_id = sentin8_current_env_id()
        );

DROP POLICY IF EXISTS flags_select ON ledger.flags;
CREATE POLICY flags_select ON ledger.flags FOR SELECT USING (
            sentin8_context_initialized()
            AND (
                (sentin8_has_scope('holder:view-all') = FALSE
                    AND env_id = sentin8_current_env_id()
                    AND customer_id IN (
                      SELECT id FROM ledger.customers
                      WHERE sentin8_auth_user_id = sentin8_current_sentin8_auth_user_id()
                    ))
                OR (sentin8_has_scope('holder:view-all')
                    AND sentin8_current_token_tp() = 'm2m'
                    AND env_id = sentin8_current_env_id())
            )
        );
DROP POLICY IF EXISTS flags_insert ON ledger.flags;
CREATE POLICY flags_insert ON ledger.flags FOR INSERT WITH CHECK (
            sentin8_context_initialized()
            AND env_id = sentin8_current_env_id()
        );
DROP POLICY IF EXISTS flags_update ON ledger.flags;
CREATE POLICY flags_update ON ledger.flags FOR UPDATE USING (
            sentin8_context_initialized()
            AND env_id = sentin8_current_env_id()
        );
DROP POLICY IF EXISTS flags_delete ON ledger.flags;
CREATE POLICY flags_delete ON ledger.flags FOR DELETE USING (
            sentin8_context_initialized()
            AND env_id = sentin8_current_env_id()
        );

DROP POLICY IF EXISTS restriction_sets_select ON ledger.restriction_sets;
CREATE POLICY restriction_sets_select ON ledger.restriction_sets FOR SELECT USING (
            sentin8_context_initialized()
            AND (
                (sentin8_has_scope('holder:view-all') = FALSE
                    AND env_id = sentin8_current_env_id()
                    AND customer_id IN (
                      SELECT id FROM ledger.customers
                      WHERE sentin8_auth_user_id = sentin8_current_sentin8_auth_user_id()
                    ))
                OR (sentin8_has_scope('holder:view-all')
                    AND sentin8_current_token_tp() = 'm2m'
                    AND env_id = sentin8_current_env_id())
            )
        );
DROP POLICY IF EXISTS restriction_sets_insert ON ledger.restriction_sets;
CREATE POLICY restriction_sets_insert ON ledger.restriction_sets FOR INSERT WITH CHECK (
            sentin8_context_initialized()
            AND env_id = sentin8_current_env_id()
        );
DROP POLICY IF EXISTS restriction_sets_update ON ledger.restriction_sets;
CREATE POLICY restriction_sets_update ON ledger.restriction_sets FOR UPDATE USING (
            sentin8_context_initialized()
            AND env_id = sentin8_current_env_id()
        );
DROP POLICY IF EXISTS restriction_sets_delete ON ledger.restriction_sets;
CREATE POLICY restriction_sets_delete ON ledger.restriction_sets FOR DELETE USING (
            sentin8_context_initialized()
            AND env_id = sentin8_current_env_id()
        );

-- ── Per-service role grants + search_path (F1 — §4.3e) ──────────────────
-- The ledger connects via its own PostgreSQL role (bank8_ledger_service,
-- created + granted by `sentin8-cli vertical enroll` from this service's
-- --print-registration --section=pg_roles). RLS only ENFORCES when the
-- service does NOT bypass it — the superuser and NOBYPASSRLS-violating
-- roles make every policy above inert. These grants give the role table
-- access; the RLS policies scope the rows.
-- The search_path puts the service's OWN schema FIRST (outbox/audit_journal
-- resolution for the shell's relay + journal pusher; unqualified ledger_*
-- domain tables resolve here too), then public (RLS helpers). The
-- `vertical enroll` never-clobber block preserves this role-level setting.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bank8_ledger_service') THEN
        ALTER ROLE bank8_ledger_service SET search_path = ledger, public;
        GRANT USAGE ON SCHEMA ledger TO bank8_ledger_service;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ledger TO bank8_ledger_service;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ledger TO bank8_ledger_service;
    END IF;
END $$;

-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: ledger rows are appended to the outbox in the SAME
-- transaction as the domain change; the shell's post-commit relay pushes
-- them to Bus POST /v1/produce (idempotency_key = row id).
-- Generated from sentin8-outbox::outbox_table_sql("ledger").
CREATE TABLE IF NOT EXISTS ledger.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_outbox_unrelayed
    ON ledger.outbox (created_at) WHERE relayed = false;
ALTER TABLE ledger.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON ledger.outbox;
CREATE POLICY outbox_select ON ledger.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON ledger.outbox;
CREATE POLICY outbox_insert ON ledger.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON ledger.outbox;
CREATE POLICY outbox_update ON ledger.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION ledger.ledger_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('ledger_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON ledger.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON ledger.outbox
    FOR EACH ROW
    EXECUTE FUNCTION ledger.ledger_notify_outbox();

-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit.
-- Generated from sentin8-audit::audit_journal_sql("ledger").
CREATE TABLE IF NOT EXISTS ledger.audit_journal (
    id              UUID PRIMARY KEY,
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ledger_audit_journal_unpushed
    ON ledger.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE ledger.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON ledger.audit_journal;
CREATE POLICY audit_journal_dml ON ledger.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- Outbox + journal role grants (same F1 pattern as the table grants above).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bank8_ledger_service') THEN
        GRANT USAGE ON SCHEMA ledger TO bank8_ledger_service;
        GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA ledger TO bank8_ledger_service;
    END IF;
END $$;
