// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! DB-backed handler-path tests (runtime-skip) — ledger DESIGN.md §9.
//!
//! Exercises the ledger's SQL seams (account CRUD, posting batch
//! commit, balances UPSERT, idempotency conflict, double-entry
//! arithmetic) against a live PostgreSQL using the same SQL the
//! handlers run. Skipped at runtime when `DATABASE_URL` is not
//! reachable (plain `cargo test` without infra), matching the
//! platform's TEST-SYS-3 pattern.
//!
//! These tests do NOT test the handlers' HTTP/auth/policy layers —
//! those are covered by the policy suites and e2e. This layer owns the
//! DB round-trips: the exact statements a handler runs, including the
//! RLS tenant-context discipline (context set on the same connection
//! as the query).

use sqlx::Acquire;
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Connect to the test database (the bank8 vertical database when
/// provisioned, else the default dev URL). Returns `None` when the
/// database is unreachable — the suite skips instead of failing.
async fn test_pool() -> Option<PgPool> {
    let url = std::env::var("BANK8_LEDGER_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://bank8_ledger_service@localhost:5432/bank8".into());
    match sqlx::PgPool::connect(&url).await {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("skipping DB-backed ledger tests — no database: {e}");
            None
        }
    }
}

/// Seed one env-scoped product + account row directly (the handler path
/// the account-opening flow exercises), then read it back through the
/// same SELECT shape `list_accounts` runs.
#[tokio::test]
async fn account_insert_and_list_roundtrip() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let env_id = Uuid::new_v4();
    let product_id = Uuid::new_v4();
    let mut conn = pool.acquire().await.expect("conn");
    // set_config(..., true) is transaction-local: the context-set and every
    // dependent INSERT share ONE explicit transaction (the begin_tenant_tx
    // handler discipline). An autocommit connection would drop the context
    // between statements and the FORCE RLS policies would reject the row.
    let mut tx = conn.begin().await.expect("tx");
    // M2M service context (token_tp=m2m + holder:view-all scope): the same
    // 9-arg shape set_tenant_context runs — the accounts holder-scoped
    // SELECT policy admits an env-wide read only from this branch.
    sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, 'm2m', 'holder:view-all', false, false, false, NULL, 'ledger')")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .expect("tenant context");

    sqlx::query(
        r#"INSERT INTO ledger.products (id, env_id, name, product_type, status, parameters, modules)
           VALUES ($1, $2, 'test-product', 'current_account', 'active', '{}', '[]')"#,
    )
    .bind(product_id)
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .expect("insert product");

    let account_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO ledger.accounts (id, env_id, product_id, product_type, nickname, status, denomination, account_type)
           VALUES ($1, $2, $3, 'current_account', 'test-account', 'active', 'CAD', 'customer')"#,
    )
    .bind(account_id)
    .bind(env_id)
    .bind(product_id)
    .execute(&mut *tx)
    .await
    .expect("insert account");

    // Read back through the list_accounts SELECT shape (same transaction).
    let rows = sqlx::query(
        r#"SELECT a.id, a.env_id, a.customer_id, a.product_id, a.account_type, a.product_type,
                  a.nickname, a.status, a.denomination, a.opened_at, a.closed_at, a.created_at
             FROM ledger.accounts a
            WHERE a.deleted_at IS NULL
              AND a.env_id = $1
              AND ($2::text IS NULL OR a.account_type = $2)
            ORDER BY a.created_at DESC LIMIT 100"#,
    )
    .bind(env_id)
    .bind("customer")
    .fetch_all(&mut *tx)
    .await
    .expect("list accounts");
    tx.commit().await.expect("commit");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<Uuid, _>("id"), account_id);
    assert_eq!(rows[0].get::<String, _>("status"), "active");
}

/// The posting seam: double-entry balances UPSERT + instruction insert
/// + transaction rows, all in one transaction, then read-back
/// verification (the read-your-writes check behind the §8.4 incident
/// class).
#[tokio::test]
async fn posting_batch_commit_and_readback() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let env_id = Uuid::new_v4();
    let mut conn = pool.acquire().await.expect("conn");
    // Context-set + seed inserts share one explicit transaction
    // (transaction-local set_config — see handlers.rs::begin_tenant_tx).
    let mut seed = conn.begin().await.expect("seed tx");
    // M2M service context (see set_tenant_context in handlers.rs).
    sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, 'm2m', 'holder:view-all', false, false, false, NULL, 'ledger')")
        .bind(env_id)
        .execute(&mut *seed)
        .await
        .expect("tenant context");

    let product_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO ledger.products (id, env_id, name, product_type, status, parameters, modules)
           VALUES ($1, $2, 'test-product', 'current_account', 'active', '{}', '[]')"#,
    )
    .bind(product_id)
    .bind(env_id)
    .execute(&mut *seed)
    .await
    .expect("insert product");

    let debit = Uuid::new_v4();
    let credit = Uuid::new_v4();
    for id in [debit, credit] {
        sqlx::query(
            r#"INSERT INTO ledger.accounts (id, env_id, product_id, product_type, nickname, status, denomination, account_type)
               VALUES ($1, $2, $3, 'current_account', 'test-account', 'active', 'CAD', 'customer')"#,
        )
        .bind(id)
        .bind(env_id)
        .bind(product_id)
        .execute(&mut *seed)
        .await
        .expect("insert account");
    }
    seed.commit().await.expect("seed commit");

    let posting_id = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("tx");
    // M2M service context (see set_tenant_context in handlers.rs) — the
    // second transaction re-sets the context (transaction-local config).
    sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, 'm2m', 'holder:view-all', false, false, false, NULL, 'ledger')")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .expect("tenant context in tx");

    sqlx::query(
        r#"INSERT INTO ledger.postings (id, env_id, batch_id, status, instruction_count)
           VALUES ($1, $2, 'test-batch', 'accepted', 1)"#,
    )
    .bind(posting_id)
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .expect("insert posting");

    sqlx::query(
        r#"INSERT INTO ledger.posting_instructions (id, env_id, posting_id, instruction_type, debit_account, credit_account, amount, denomination, status)
           VALUES ($1, $2, $3, 'DEPOSIT', $4, $5, $6::numeric, 'CAD', 'accepted')"#,
    )
    .bind(Uuid::new_v4())
    .bind(env_id)
    .bind(posting_id)
    .bind(debit)
    .bind(credit)
    .bind("500.00")
    .execute(&mut *tx)
    .await
    .expect("insert instruction");

    // Double-entry balances: debit -500, credit +500 (COMMITTED, DEFAULT).
    for (account, delta) in [(debit, "-500.00"), (credit, "500.00")] {
        sqlx::query(
            r#"INSERT INTO ledger.balances (env_id, account_id, denomination, address, phase, amount)
               VALUES ($1, $2, 'CAD', 'DEFAULT', 'COMMITTED', $3::numeric)
               ON CONFLICT (account_id, denomination, address, phase)
               DO UPDATE SET amount = balances.amount + ($3::numeric), updated_at = now()"#,
        )
        .bind(env_id)
        .bind(account)
        .bind(delta)
        .execute(&mut *tx)
        .await
        .expect("balance upsert");
    }

    sqlx::query(
        r#"INSERT INTO ledger.transactions (id, env_id, account_id, posting_id, amount, denomination, direction)
           VALUES ($1, $2, $3, $4, $5::numeric, 'CAD', $6)"#,
    )
    .bind(Uuid::new_v4())
    .bind(env_id)
    .bind(debit)
    .bind(posting_id)
    .bind("500.00")
    .bind("debit")
    .execute(&mut *tx)
    .await
    .expect("insert transaction");
    tx.commit().await.expect("commit");

    // Read-back verification on a pooled (fresh) connection — the exact
    // check `create_posting` runs after commit. The fresh connection has
    // no tenant context: re-set it inside an explicit transaction (FORCE
    // RLS rejects context-less reads) using the M2M service shape.
    let readback: (String, i64) = {
        let mut r = pool.acquire().await.expect("readback conn");
        let mut rtx = r.begin().await.expect("readback tx");
        sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, 'm2m', 'holder:view-all', false, false, false, NULL, 'ledger')")
            .bind(env_id)
            .execute(&mut *rtx)
            .await
            .expect("readback context");
        let v = sqlx::query_as(
            r#"SELECT COALESCE(split_part(current_setting('search_path'), ',', 1), ''),
                      (SELECT count(*)::bigint FROM ledger.postings WHERE id = $1)"#,
        )
        .bind(posting_id)
        .fetch_one(&mut *rtx)
        .await
        .expect("readback");
        rtx.commit().await.expect("readback commit");
        v
    };
    assert_eq!(readback.1, 1, "posting row must be visible after commit");

    let (debit_amount, credit_amount): (rust_decimal::Decimal, rust_decimal::Decimal) = {
        let mut r = pool.acquire().await.expect("balance conn");
        let mut rtx = r.begin().await.expect("balance tx");
        sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, 'm2m', 'holder:view-all', false, false, false, NULL, 'ledger')")
            .bind(env_id)
            .execute(&mut *rtx)
            .await
            .expect("balance context");
        let d: rust_decimal::Decimal = sqlx::query_scalar(
            r#"SELECT amount FROM ledger.balances WHERE account_id = $1 AND denomination = 'CAD' AND address = 'DEFAULT' AND phase = 'COMMITTED'"#,
        )
        .bind(debit)
        .fetch_one(&mut *rtx)
        .await
        .expect("debit balance");
        let c: rust_decimal::Decimal = sqlx::query_scalar(
            r#"SELECT amount FROM ledger.balances WHERE account_id = $1 AND denomination = 'CAD' AND address = 'DEFAULT' AND phase = 'COMMITTED'"#,
        )
        .bind(credit)
        .fetch_one(&mut *rtx)
        .await
        .expect("credit balance");
        rtx.commit().await.expect("balance commit");
        (d, c)
    };
    assert_eq!(debit_amount, rust_decimal::Decimal::from(-500));
    assert_eq!(credit_amount, rust_decimal::Decimal::from(500));
}

/// Idempotency: a duplicate `(env_id, idempotency_key)` posting returns
/// the ORIGINAL row (ON CONFLICT), never a second posting.
#[tokio::test]
async fn posting_idempotency_conflict_returns_original() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let env_id = Uuid::new_v4();
    let mut conn = pool.acquire().await.expect("conn");
    // Context-set + both idempotent inserts share one explicit transaction
    // (transaction-local set_config — the begin_tenant_tx discipline).
    let mut tx = conn.begin().await.expect("tx");
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .expect("tenant context");

    let key = format!("e2e-idem-{}", Uuid::new_v4());
    let first = sqlx::query(
        r#"INSERT INTO ledger.postings (id, env_id, batch_id, status, idempotency_key, instruction_count)
           VALUES ($1, $2, $4, 'accepted', $3, 1)
           ON CONFLICT (env_id, idempotency_key) WHERE idempotency_key IS NOT NULL
           DO UPDATE SET batch_id = postings.batch_id
           RETURNING id"#,
    )
    .bind(Uuid::new_v4())
    .bind(env_id)
    .bind(&key)
    .bind("test-batch")
    .fetch_one(&mut *tx)
    .await
    .expect("first insert");
    let original_id: Uuid = first.get("id");

    let second = sqlx::query(
        r#"INSERT INTO ledger.postings (id, env_id, batch_id, status, idempotency_key, instruction_count)
           VALUES ($1, $2, 'test-batch', 'accepted', $3, 1)
           ON CONFLICT (env_id, idempotency_key) WHERE idempotency_key IS NOT NULL
           DO UPDATE SET batch_id = ledger.postings.batch_id
           RETURNING id"#,
    )
    .bind(Uuid::new_v4())
    .bind(env_id)
    .bind(&key)
    .bind("test-batch")
    .fetch_one(&mut *tx)
    .await
    .expect("second insert");
    let returned_id: Uuid = second.get("id");
    assert_eq!(
        returned_id, original_id,
        "duplicate idempotency key must return the original posting"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM ledger.postings WHERE env_id = $1 AND idempotency_key = $2",
    )
    .bind(env_id)
    .bind(&key)
    .fetch_one(&mut *tx)
    .await
    .expect("count");
    assert_eq!(count, 1, "exactly one posting row must exist");
    tx.commit().await.expect("commit");
}

/// RLS discipline: context-set and the dependent query share one
/// transaction — a different connection without context sees nothing
/// (FORCE RLS), and the outbox insert path works under the same context.
#[tokio::test]
async fn rls_context_isolation_and_outbox_insert() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let env_id = Uuid::new_v4();

    // Connection A: context + insert inside ONE explicit transaction —
    // set_config(..., true) is transaction-local, so the context-set, the
    // INSERT and the visibility probe must share the transaction (the
    // begin_tenant_tx handler discipline).
    let mut a = pool.acquire().await.expect("conn a");
    let mut txa = a.begin().await.expect("tx a");
    // M2M service context (see set_tenant_context in handlers.rs).
    sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, 'm2m', 'holder:view-all', false, false, false, NULL, 'ledger')")
        .bind(env_id)
        .execute(&mut *txa)
        .await
        .expect("context a");
    sqlx::query(
        "INSERT INTO ledger.accounts (id, env_id, product_id, product_type, nickname, status, denomination, account_type)
         VALUES ($1, $2, $2, 'current_account', 'rls-test', 'active', 'CAD', 'customer')",
    )
    .bind(Uuid::new_v4())
    .bind(env_id)
    .execute(&mut *txa)
    .await
    .expect("insert under context");

    let visible_a: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM ledger.accounts WHERE env_id = $1")
            .bind(env_id)
            .fetch_one(&mut *txa)
            .await
            .expect("count a");
    assert_eq!(visible_a, 1, "same-connection query must see the row");

    // Connection B without context: sees nothing (context_initialized false).
    // Both probes run inside explicit transactions — set_config(..., true)
    // is transaction-local, so the isolation boundary is only observable
    // when each acquire's read happens in its own tx (matching the
    // begin_tenant_tx handler pattern).
    let visible_b: i64 = {
        let mut b = pool.acquire().await.expect("conn b");
        let mut tx = b.begin().await.expect("tx b");
        let v =
            sqlx::query_scalar("SELECT count(*)::bigint FROM ledger.accounts WHERE env_id = $1")
                .bind(env_id)
                .fetch_one(&mut *tx)
                .await
                .expect("count b");
        tx.commit().await.expect("commit b");
        v
    };
    assert_eq!(
        visible_b, 0,
        "context-less connection must see nothing (FORCE RLS)"
    );

    // Outbox insert under the same context (the DBX producer path).
    let outbox_id = sentin8::bus::outbox::insert_outbox_row(
        &mut *txa,
        env_id,
        "ledger",
        "bank8:ledger:account:created",
        &serde_json::json!({ "account_id": Uuid::new_v4().to_string() }),
    )
    .await
    .expect("outbox insert");
    // The relay drains rows with `relayed = false` — a fresh row is unrelayed.
    let relayed: bool = sqlx::query_scalar("SELECT relayed FROM ledger.outbox WHERE id = $1")
        .bind(outbox_id)
        .fetch_one(&mut *txa)
        .await
        .expect("outbox row read");
    assert!(!relayed, "fresh outbox rows start unrelayed");
    // Commit A: the outbox row must be durable BEFORE the relay's
    // unrelayed-env scan runs (a fresh transaction sees committed rows).
    txa.commit().await.expect("commit a");
    // The owner-side SECURITY DEFINER helper (bare-pool safe) sees the
    // seeded env — this is exactly the list the shell's DBX relay polls.
    let envs: Vec<Uuid> =
        sqlx::query_scalar("SELECT DISTINCT env_id FROM sentin8_outbox_unrelayed_envs('ledger')")
            .fetch_all(&pool)
            .await
            .unwrap_or_default();
    assert!(
        envs.contains(&env_id),
        "the seeded outbox row must appear in the relay's unrelayed-env list"
    );
}

/// Schedules: the due-schedule SQL seam the Cron proxy-back exercises —
/// insert a schedule, verify the due-window SELECT finds it.
#[tokio::test]
async fn schedule_due_window_select() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let env_id = Uuid::new_v4();
    let mut conn = pool.acquire().await.expect("conn");
    // Context-set + insert + due-window scan share one explicit transaction
    // (transaction-local set_config — the begin_tenant_tx discipline).
    let mut tx = conn.begin().await.expect("tx");
    // M2M service context (see set_tenant_context in handlers.rs).
    sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, 'm2m', 'holder:view-all', false, false, false, NULL, 'ledger')")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .expect("context");

    sqlx::query(
        r#"INSERT INTO ledger.schedules (id, env_id, schedule_type, status, next_run_at, cron_expression)
           VALUES ($1, $2, 'posting', 'active', now() + interval '1 minute', '0 0 * * *')"#,
    )
    .bind(Uuid::new_v4())
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .expect("insert schedule");

    // A due-window scan (the internal/schedules/run seam): the schedule
    // whose next_run_at has passed (or passes within the window) and is
    // active must be found.
    let due: i64 = sqlx::query_scalar(
        r#"SELECT count(*)::bigint FROM ledger.schedules
            WHERE env_id = $1 AND status = 'active' AND next_run_at <= now() + interval '1 minute'"#,
    )
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .expect("due count");
    assert_eq!(due, 1, "the fresh schedule must be inside the due window");
    tx.commit().await.expect("commit");
}
