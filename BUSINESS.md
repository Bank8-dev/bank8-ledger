# Bank8:Ledger - Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Bank8:Ledger **does for the business**. For architecture read `README.md`;
> for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

Bank8:Ledger is the **system of record for money positions** in the bank8
vertical. It delivers:

- **Truthful balances** - every money movement is captured atomically as a
  double-entry posting batch; a batch that does not balance is rejected
  before anything is written, so the books can never drift.
- **A complete product factory** - bank products (current accounts, savings,
  cards, loans) are data, not code: they compose reusable validation modules
  whose parameters resolve through a global → product → account hierarchy,
  letting the bank launch and change products without engineering work.
- **Time-driven money movement** - recurring charges, interest accrual,
  dormancy fees, sweeps, and statement generation run on schedules without
  human hands on.
- **A provable, replayable trail** - every account, posting, schedule,
  and configuration change is journaled, checksum-chained, and auditable;
  regulatory reconciliation never depends on an engineer reading a database.
- **Operational safety at scale** - bulk account updates/migrations,
  processing-group pause/resume, a local dead-letter queue with replay, and
  idempotent APIs that make retry safe by design.

## 2. Business Scope (What the Service Provides)

| # | Capability area | What the business gets |
|---|---|---|
| 1 | Customer records | Banking customer registry, optionally linked to a platform sign-in identity |
| 2 | Accounts | Open/close/manage customer and internal accounts, with balances, transactions, statements, schedules, attributes, and payment devices |
| 3 | Products | Product library with versioned parameters, validation modules, activation lifecycle, and plan assignment + migration |
| 4 | Postings | Synchronous and asynchronous double-entry posting batches with idempotency, dry-run, post-failure republish, and reversal via adjustments |
| 5 | Balances | Live and end-of-day balances plus balance time series per account |
| 6 | Configuration library | Parameters, flags, restrictions, and their resolution hierarchy (global → product → account) |
| 7 | Calendars | Business-day calendars, calendar events/periods, and bookkeeping-date resolution |
| 8 | Schedules & jobs | Scheduled-posting engine with due-scan, job log, retry, batch republish, and a local dead-letter queue with replay |
| 9 | Statements | Scheduled per-account-period statement documents (stored in Sentin8:Storage) and regeneration on demand |
| 10 | Contracts | Contract module/event registry, contract simulation, cross-account supervisor contracts |
| 11 | Adjustments | Post-posting corrections with reason codes and bulk retry |
| 12 | Bulk operations | Account migrations and account update batches with per-item retry |
| 13 | Processing control | Processing groups with pause/resume for batch processing windows |
| 14 | Journal & replay | Replayable domain journal with checksum chain and event replay |
| 15 | Audit | Domain audit trail, action logs, and stream inspection |
| 16 | Admin console | 19 admin pages (overview, accounts, postings, products, schedules, DLQ, reconcile, balances, parameters, restrictions, flags, customers, statements, settings, policy sets, policy decisions, relations, attributes) rendered remotely in the platform dashboard |
| 17 | Domain events | 30 outbound event types covering every lifecycle change, consumed by Payments and other vertical consumers |
| 18 | Health | Service health endpoint for fleet supervision |

**What the service does NOT own (business boundary):**

| Out of scope | Owned by |
|---|---|
| Scheduling / timing of scheduled work | Sentin8:Cron (the ledger provides the due-batch execution) |
| Tenant-authored executable hooks (custom compliance/user logic) | Sentin8:Func (the ledger executes modules it references) |
| Multi-step workflow orchestration (e.g. statement regeneration retries) | Sentin8:Flow |
| Customer identity, sign-in, sessions | Sentin8:Auth (the ledger links records to identities) |
| Payment instruction processing (initiation, routing, clearing) | Bank8:Payments (it consumes ledger postings and calls back for movement) |
| Analytics dashboards / KPI computation | Sentin8:Stat (the ledger feeds metrics) |
| Object storage of statement documents | Sentin8:Storage (the ledger writes/composes) |
| Event transport, durability, delivery, DLQ-for-consumers | Sentin8:Bus (the ledger only produces) |
| API proxying to client apps | Sentin8:BFF |

## 3. Business Capabilities

### 3.1 Customers

| Capability | Business rule |
|---|---|
| Register a banking customer | Any tenant can record customers with display name and identity linkage fields |
| Link customer to platform identity | A customer may be linked to a Sentin8:Auth user id; one identity linkage per customer |
| Update customer details | Updates are journaled; `customer:updated` is emitted |

### 3.2 Accounts

| Capability | Business rule |
|---|---|
| Open account | An account must reference an active product; customer accounts must reference a customer; internal accounts may be customer-less |
| Account types | Two kinds: `CUSTOMER` (banking accounts held by customers) and `INTERNAL` (the bank's own counterparty accounts) |
| Account status model | `PENDING → OPEN → CLOSING → CLOSED` (plus `CANCELLED`); every transition is guarded - a closed account never reopens |
| Balance-sheet side (`tside`) | Each account is `ASSET` (debits increase the balance - loans, cards) or `LIABILITY` (credits increase it - deposits); posting direction semantics follow the side, so debits/credits are never mis-signed |
| Multi-currency | An account has a primary denomination (CAD default) plus `permitted_denominations` for the currencies it may hold |
| Shared access | `stakeholder_ids` let multiple customers share one account (joint accounts) |
| Nickname | Customer-facing account names ("Everyday", "Vacation fund") without touching product data |
| Instance parameter overrides | Per-account `instance_param_vals` override product-level settings for one account (e.g. a negotiated fee waiver) without a new product version |
| Tenant hook binding | An account can bind a Sentin8:Func version (`sentin8_func_version_id`) for tenant-authored posting-time logic, with a pending slot for zero-downtime upgrades |
| Account numbering | Account numbers are generated per product; unique within the environment |
| Balances & transactions | Every account exposes its current balances (by denomination/address/phase), its full transaction history, and paged statements |
| Payment devices | Each account can carry registered payment devices (e.g. cards) for payment routing |
| Attributes | Key-value account attributes extend account data without schema changes |
| Schedule tags | Accounts can be tagged for schedule routing/selection so schedules target groups, not one-by-one lists |

#### 3.2.1 Internal (counterparty) accounts

When the ledger is enabled for a tenant, a standard set of internal
accounts is seeded **per denomination** (CAD, USD, EUR, GBP, AUD, MYR,
SGD, AED) so every interest accrual, fee, penalty, and teller movement
has a real counterparty. The bank itself is registered as an explicit
`institution` customer (one per environment) that owns these accounts -
internal accounts are never customer-less, yet remain invisible to
customer holders.

| Group | Seeded accounts |
|---|---|
| Interest | Interest Paid · Interest Received · Accrued Interest Payable · Accrued Interest Receivable · Capitalised Interest Received/Receivable · Overdraft Interest Receivable/Received |
| Fee income | Late Repayment Fee Income · Early Repayment Fee Income · Upfront Fee Income · Overpayment Fee Income · Maintenance Fee Income · Minimum Balance Fee Income · Inactivity Fee Income · Excess Fee Income · Overlimit Fee Income · Annual Fee Income · Paper Statement Fee Income · Early Closure Fee Income · Payment Type Fee Income · Unarranged Overdraft Fee Income/Receivable · Overpayment Allowance Fee Income · Fee Rebate |
| Penalties & write-offs | Penalty Interest Received · Capitalised Penalties Received · Interest Write-off · Principal Write-off · Interest on Fees |
| Teller counterparties | Cash Deposit · Cheque Clearing · Liquidity · Clearing · Suspense (the accounts eTeller resolves for teller cash/cheque postings) |
| Other | Deposit Account · Line of Credit Account · Profit Paid · Accrued Profit Payable (Shariah products) |

Product settings reference these accounts by ID (see the
`*_income_account` parameters in §3.3.1) - every fee and interest amount
books to an auditable income/expense account, never to a magic
destination.

### 3.3 Products

| Capability | Business rule |
|---|---|
| Product creation | A product declares a type, a parameter set, and a list of validation modules |
| Versioning | Every product change creates a new version; existing accounts keep the version they were opened with until migrated |
| Activation | Only an activated product can open accounts; activation is a distinct, audited action |
| Plans | Accounts are assigned plans; plan migrations move accounts between plans in audited batches |
| Validation modules | Reusable rule modules (limits, overdraft rules, tiered rates, fee schedules, dormancy, sweeps) validate account lifecycle and posting behaviour |
| Type-specific validation | Product parameters are validated against the schema of their product type (e.g. credit limit must be > 0; mortgage due-day must be 1-28; savings interest rate must be ≥ 0) - a misconfigured product is rejected at creation, not at the customer's first posting |
| Admin catalog | The admin console offers a 13-type product catalog with pre-selected default modules and typed settings forms, so a product manager configures rather than codes |

#### 3.3.1 Product type catalog - the 13 built-in product types

Every product type carries a balance-sheet side, supported currencies,
a default module set, and its own settings. Representative settings and
defaults (all overridable per product / per account):

| Product type | Side | Currencies | Signature settings (defaults) |
|---|---|---|---|
| **Current account** | Liability | CAD USD EUR GBP | Interest rate (0.1%), overdraft limit (500), monthly maintenance fee (5.00), inactivity fee (2.00), maximum balance (1,000,000), interest application frequency (daily/monthly/quarterly/annually) + per-fee income-account wiring |
| **Savings account** | Liability | CAD USD EUR GBP | Interest rate (2%, tiered via `rate_tiers`), minimum balance (100), maximum balance (5,000,000), inactivity fee (1.00), interest application frequency |
| **Credit card** | Asset | CAD USD EUR GBP | Credit limit (5,000 - must be > 0), APR (18.99%), annual fee, late repayment fee (25), overlimit fee (25), payment due period (25 days), minimum percentage due (3%) |
| **Loan** | Asset | CAD USD EUR GBP | Fixed interest rate (8.99%), amortisation method (straight line / reducing balance), repayment period (36 months), due amount calculation day (1-28), grace period (5 days), late repayment fee (15), early repayment fee rate (1%) |
| **Mortgage** | Asset | CAD USD EUR GBP AUD | Fixed rate (5.99%) with fixed-interest period (60 months) toggle, loan term (360 months), due day (1-28), grace period (15 days), late fee (50), amortisation method |
| **Home loan redraw** | Asset | CAD AUD | Variable rate (6.49%), loan term (360), redraw enabled + redraw fee, redraw limit percentage (drives available redraw funds) |
| **Line of credit** | Asset | CAD USD EUR | Credit limit (50,000), variable rate (7.99%), interest accrual rest type (daily / continuous), minimum repayment (100) |
| **BNPL loan** | Asset | CAD USD EUR GBP | Instalment count (4), instalment interval (14 days), interest-free period (42 days), late fee (10), minimum purchase amount (50) |
| **Time deposit** | Liability | CAD USD EUR GBP | Interest rate (3.5%), term (12 months - must be > 0), minimum deposit (1,000), maximum balance (1,000,000), early withdrawal penalty rate (1%) |
| **Wallet** | Liability | CAD USD EUR GBP SGD AED | Maximum balance (50,000), daily spending limit (5,000), auto top-up (enabled, threshold 100, amount 500) |
| **US checking** | Liability | CAD USD | Overdraft limit (250), monthly maintenance fee (10.00), minimum balance (500), overdraft protection via linked savings |
| **US savings** | Liability | CAD USD | Interest rate (1.5%), minimum balance (200), maximum balance (250,000), monthly fee (5.00), linked to US checking for overdraft |
| **Shariah savings** | Liability | CAD MYR | Profit rate (2.5% - profit, not interest), minimum balance (500), profit application frequency, dedicated profit-paid / accrued-profit-payable accounts |

Every fee/interest setting pairs with an income-account reference
(`*_income_account` parameters) that routes the amount to the seeded
internal accounts in §3.2.1 - fees and interest are always auditable
double-entry movements.

#### 3.3.2 The 14-module validation library

Products compose behaviour by listing modules; each module runs at
account creation, posting time, or on schedule, and is configured purely
through parameters:

| # | Module | Runs | Enforces | Parameter keys |
|---|---|---|---|---|
| 1 | `denomination-validation` | Creation | Account currency must be in the product's supported list | `supported_denominations` |
| 2 | `deposit-limits` | Creation + posting | Minimum deposit per transaction; daily deposit cap | `min_deposit_amount`, `max_daily_deposit_limit` |
| 3 | `withdrawal-limits` | Posting | Minimum withdrawal; daily withdrawal cap | `min_withdrawal_amount`, `max_daily_withdrawal_limit` |
| 4 | `transaction-type-limits` | Posting | Per-instruction-type daily caps (e.g. `max_daily_atm_withdrawal_limit`) | `max_daily_{type}_limit` |
| 5 | `maximum-balance` | Posting | Balance ceiling - deposits that would exceed it are rejected | `maximum_balance` |
| 6 | `overdraft-protection` | Posting | Debits may not push the balance below −(arranged + unarranged overdraft) | `arranged_overdraft_limit`, `unarranged_overdraft_limit` |
| 7 | `overdraft-protection-sweep` | Posting | Auto-sweep from a linked account when the balance drops below the threshold | `sweep_threshold` |
| 8 | `deposit-interest-accrual` | Schedule | Daily accrual = balance × rate ÷ 365; supports tiered rates by balance band | `rate_tiers` [{min_balance, rate}] or `interest_rate`, `accrual_precision` |
| 9 | `deposit-interest-application` | Schedule | Credits accrued interest to the customer account | `interest_application_frequency` |
| 10 | `maintenance-fees` | Schedule | Periodic maintenance fee | `maintenance_fee_amount` |
| 11 | `inactivity-fee` | Schedule | Fee after N days without activity (default threshold 90 days) | `inactivity_threshold_days`, `inactivity_fee_amount` |
| 12 | `minimum-balance-fee` | Schedule | Fee when average balance falls under the threshold | `minimum_balance_threshold`, `minimum_balance_fee_amount` |
| 13 | `closure-interest-application` | Closure/maturity | Pays accrued interest on closure, less any forfeiture | `forfeiture_rate` |
| 14 | `dormancy` | Schedule | Flags the account dormant after N days (default 365) | `dormancy_threshold_days` |

#### 3.3.3 Module composition rules (per product type)

The ledger enforces which modules make business sense for each product
type - an invalid composition is rejected at product creation:

| Product type | Disallowed modules (business reason) |
|---|---|
| Current account / US checking | None - the full 14-module catalogue is available |
| Savings / US savings / Shariah savings | `overdraft-protection`, `overdraft-protection-sweep` - savings accounts cannot have overdraft |
| Time deposit | `overdraft-protection` (no overdraft), `withdrawal-limits` (no withdrawals before maturity), `maintenance-fees` (no maintenance fees) |
| Loan / Mortgage / Home loan redraw / BNPL | `deposit-interest-accrual`/`-application`, `maintenance-fees`, `inactivity-fee`, `dormancy` - loans do not accrue deposit interest, carry maintenance fees, go inactive-fee'd, or dormant |
| Credit card | `deposit-limits`, `withdrawal-limits`, `maximum-balance`, `deposit-interest-accrual`, `dormancy` - cards do not use deposit/withdrawal limits or deposit interest |
| Line of credit / Wallet | `deposit-interest-accrual`, `dormancy` |

#### 3.3.4 Derived parameters (computed, never stored)

The ledger derives live values from template + instance parameters at
read time - they can never go stale:

| Derived value | Applies to | Computed from |
|---|---|---|
| `available_credit` | Credit cards | credit limit − current balance (floored at 0) |
| `remaining_term` | Loans, mortgages, LoC, BNPL, home-loan redraw | loan term − months since opening |
| `total_outstanding_debt` | Loan family | current balance |
| `next_repayment_date` | Loan family | `repayment_day` (1-28) → next occurrence |
| `available_redraw_funds` | Home loan redraw | balance × redraw limit percentage |
| `maturity_date` | Time deposits | opening date + term months |

### 3.4 Postings (money movement)

| Capability | Business rule |
|---|---|
| Double-entry guarantee | A posting batch must net to zero per denomination before any row is written; otherwise it is rejected (HTTP 422, nothing written) |
| Instruction types | Ten business-meaningful instruction types drive direction semantics: **debit-side** `WITHDRAWAL`, `FEE_APPLICATION`, `TRANSFER_OUT`, `REVERSAL_DEBIT`, `ADJUSTMENT_DEBIT` (charge the source account) and **credit-side** `DEPOSIT`, `INTEREST_APPLICATION`, `TRANSFER_IN`, `REVERSAL_CREDIT`, `ADJUSTMENT_CREDIT` (credit the account) - the engine signs balance deltas from the type, so a fee debits and a deposit credits by construction |
| Idempotency | A retry with the same idempotency key returns the original posting result - never a second money movement |
| Synchronous postings | Balance, transaction, posting, and instruction rows commit atomically or not at all |
| Asynchronous postings | Async requests are acknowledged only after the request event is durably enqueued (never pending-without-event) |
| Dry run | A posting can be validated without committing (fee calculation preview, limit checks) - no balances, no events, no rows |
| Module validation | Product modules run on every posting - e.g. overdraft limits block the posting |
| Value vs booking timestamps | Instructions may carry distinct value and booking timestamps (book today, value-date in the past/future per calendar rules) |
| Post-posting failures | Failed posting instructions are recorded and individually republishable |
| Adjustments | Corrections happen as explicit adjustment records with reason codes - the original posting is never mutated |
| Reversal | A completed posting can be reversed by a compensating posting; the original record stays intact |

### 3.5 Balances

| Capability | Business rule |
|---|---|
| Live balances | Real-time balances per account, keyed by (denomination, address, phase) - the three-dimensional balance model |
| Phases | `COMMITTED` (settled money), `PENDING_IN`, `PENDING_OUT` (in-flight holds) - available vs settled balances are distinct facts |
| End-of-day balances | Closing balances per bookkeeping date, used for statements and reconciliation |
| Balance series | Historical balance series for reporting and trend analysis |
| Concurrency | Concurrent postings on one account serialize on the balance row - no lost updates |

### 3.6 Configuration library

| Capability | Business rule |
|---|---|
| Parameters | Named parameters with typed values; effective values resolve global → product → account |
| Effective-value view | Business users ask "what does this parameter equal for this account right now" and get the hierarchy-resolved answer (cached for read speed) |
| Flags | Flag definitions instantiated per account (e.g. block debits, waive fees) |
| Restrictions | Restriction definitions instantiated per account as hard behavioural limits |
| Auditability | Every configuration change emits an event and is journal-able |

### 3.7 Calendars

| Capability | Business rule |
|---|---|
| Business calendars | Calendars define business days, holidays, and periods per tenant |
| Bookkeeping dates | Any date resolves to the correct booking date via calendar rules - value-date vs booking-date skew is systematic, not ad-hoc |
| Events & periods | Calendar events (holidays, closures) and periods (statement cycles) drive schedules and statements |

### 3.8 Schedules & jobs

| Capability | Business rule |
|---|---|
| Scheduled postings | Due schedules generate posting batches with double-entry validation, submitted through the same engine as `POST /v1/postings` |
| Concrete schedule families | `interest_accrual` (daily accrual, tiered rates), `interest_application` (credits accrued interest), `fee_application` (maintenance + inactivity + minimum-balance fees in one batch), `dormancy` (sets the `ACCOUNT_DORMANT` flag after the threshold), `statement`/`statement_generation` (period documents to Storage), `maturity_processing`/`closure` (closure interest with forfeiture) |
| Scope | A schedule targets one account or the whole environment (all active customer accounts, capped per run) |
| Schedule-retry safety | Every generated batch carries an idempotency key derived from schedule + UTC date - a Cron retry on the same day can never double-apply a fee or interest |
| Job log | Every generated batch/job is logged with status; failed jobs are individually retried or batch-republished |
| Local DLQ | A dead-letter queue captures failed scheduled work for manual review and replay |
| Timing delegated | When a schedule runs is decided by Sentin8:Cron; what runs is the ledger's contract |

### 3.9 Statements

| Capability | Business rule |
|---|---|
| Scheduled generation | Statements are produced per account per statement period as documents stored in Sentin8:Storage |
| Regeneration | A statement can be regenerated on demand; regeneration is a workflow with per-account retry (idempotent per account+period) |

### 3.10 Contracts

| Capability | Business rule |
|---|---|
| Contract modules | Registry of reusable contract behaviours referenced by products and schedules |
| Simulation | Contract outcomes can be simulated before being attached (what-if pricing, fee outcomes) |
| Supervisor contracts | Cross-account supervision (e.g. parent/child account oversight) with explicit contract records |

### 3.11 Bulk operations & processing control

| Capability | Business rule |
|---|---|
| Account migrations | Bulk product/plan changes are staged, applied, and retried per item |
| Account update batches | Bulk attribute/flag updates run with per-item retry |
| Processing groups | Groups of accounts can be paused/resumed to control batch windows (e.g. freeze processing during cut-over) |

### 3.12 Journal, audit & admin

| Capability | Business rule |
|---|---|
| Domain journal | Every journaled domain event is checksum-chained; tampering is detectable |
| Replay | Journal events can be replayed to rebuild downstream state |
| Audit trail | Domain writes produce audit records (actor, action, target); posting writes are fail-closed (no audit → no posting) |
| Action logs & streams | Operators inspect action logs and event streams for reconciliation |
| Admin console | All of the above is operable from the platform dashboard via remote admin pages - no direct database access for operators |

## 4. Business Events (Outbound)

Event names are the business contract - consumers subscribe on these.
Family prefix: `bank8:ledger:`.

| Event | Fires when |
|---|---|
| `bank8:ledger:posting:created` | A posting batch commits (synchronous, replay, or schedule run) |
| `bank8:ledger:posting:async:request` | An asynchronous posting request is durably enqueued |
| `bank8:ledger:posting:republished` | A failed posting is republished from the DLQ |
| `bank8:ledger:account:created` / `bank8:ledger:account:updated` | Account is opened / any account field changes |
| `bank8:ledger:product:created` / `:updated` / `:activated` | Product lifecycle changes |
| `bank8:ledger:productversion:created` | A new product version is created |
| `bank8:ledger:customer:created` / `:updated` / `:authlinked` | Customer registration, update, identity link |
| `bank8:ledger:adjustment:created` | A post-posting correction is recorded |
| `bank8:ledger:schedule:created` | A schedule is defined |
| `bank8:ledger:job:retried` / `bank8:ledger:job:batchrepublished` | Job operations on the schedule engine |
| `bank8:ledger:flagdefinition:created` / `bank8:ledger:flag:created` | Flag library / account flag instantiation |
| `bank8:ledger:restrictiondefinition:created` / `bank8:ledger:restrictionset:created` | Restriction library / account restriction set |
| `bank8:ledger:parameter:created` / `bank8:ledger:parametervalue:created` / `bank8:ledger:hierarchynode:created` | Parameter library changes |
| `bank8:ledger:calendar:created` / `bank8:ledger:calendarevent:created` / `bank8:ledger:bookkeepingdate:updated` | Calendar model changes |
| `bank8:ledger:plan:created` / `bank8:ledger:planmigration:created` | Plan lifecycle and migration batches |
| `bank8:ledger:processinggroup:updated` | A processing group is paused or resumed |
| `bank8:ledger:internalaccount:created` | An internal (counterparty) account is created |
| `bank8:ledger:paymentdevice:created` | A payment device is registered on an account |
| `bank8:ledger:supervisorcontract:created` | A supervisor contract is established |
| `bank8:ledger:scheduletag:created` | A schedule tag is defined |

**Inbound (consumed):**

| Event | Consumer behaviour |
|---|---|
| `sentin8:sys:service:updated` | Environment-initialization reactions (e.g. seeding internal accounts when a service is enabled for a tenant) |

## 5. Business Rules & Invariants

1. **The books always balance.** Every posting batch nets to zero per
   denomination; an unbalanced batch is rejected before any write.
2. **Money movement is atomic.** Balances, transactions, postings,
   instructions, audit, and the event outbox commit in one transaction -
   there is no such thing as a half-posting.
3. **Retries are safe.** A posting retried with the same idempotency key
   returns the original result - money never moves twice for the same
   request.
4. **Money is never approximate.** All money values are exact decimals
   (no floating-point) end-to-end, on the wire and in storage.
5. **Terminal states are final.** Completed postings, terminal
   instructions, and closed accounts never regress to an earlier state.
6. **Corrections, not edits.** A posted entry is never mutated; corrections
   are explicit adjustment records (or compensating postings) with reasons.
7. **Audit is fail-closed.** On the posting path, if the audit row or the
   event-outbox row cannot be written, the whole posting aborts -
   unaudited money movement cannot exist.
8. **The journal is tamper-evident.** Journal events are checksum-chained;
   any modification breaks the chain and is detectable.
9. **Tenant isolation is absolute.** Every record is environment-scoped
   and row-level-security enforced; a tenant can only ever see and touch
   its own data. Cross-tenant requests are rejected, never defaulted.
10. **Configuration resolves deterministically.** A parameter resolves
    global → product → account, and the same question always yields the
    same answer for the same (account, date).
11. **Internal counterparties exist per denomination.** Cash, cheque,
    liquidity, clearing, and suspense accounts are seeded so every posting
    has a real counterparty - no magic destinations.
12. **Authorization precedes execution.** Every API call passes the
    platform authorization pipeline with live-resolved roles; permission
    changes take effect on the next request.

## 6. Target-User Roles & Use Cases

| Persona | What they do with Bank8:Ledger |
|---|---|
| Retail bank customer (via eBank app) | Sees balances and transaction history; receives statements; benefits from product rules (limits, fees) without touching them |
| Bank teller / operations staff (via eTeller) | Opens accounts, registers customers, posts manual entries (e.g. cash deposit), performs adjustments |
| Product manager | Defines products and versions, composes validation modules, sets parameters/flags/restrictions, plans and plan migrations; simulates contracts before launch |
| Treasury / finance ops | Uses internal accounts, end-of-day balances, reconcile page, processing groups, and adjustments for daily reconciliation and cut-over control |
| Scheduler operator | Manages schedules, monitors the job log, retries/batch-republishes failed jobs, replays DLQ entries |
| Compliance / auditor | Reads the audit trail, action logs, and checksum-chained journal; replays events to verify history |
| Platform admin | Uses the 19 admin pages in the dashboard; manages DLQ and policy views |
| Downstream services (Payments, FDX, apps) | Subscribe to `bank8:ledger:*` events; query accounts/balances through the public API |

## 7. KPIs / Success Criteria

- **Balance integrity**: zero unbalanced posting batches committed; zero
  reconciliation breakage attributable to the ledger.
- **Posting correctness**: zero duplicate money movements under client
  retry (idempotency coverage = 100% of posting calls).
- **Availability**: the ledger is a system of record - posting path
  availability matches the platform SLA; no lost postings on crash
  (atomicity is structural).
- **Event delivery**: 100% of domain changes eventually reach Sentin8:Bus
  (outbox relay with retry budget; manual replay as backstop).
- **Statement timeliness**: statements generated for every account by the
  scheduled deadline; regeneration completes within the workflow SLA.
- **Audit completeness**: every domain write carries an audit record; the
  journal chain never breaks.
- **Read performance**: balance and effective-parameter reads served from
  indexed/cached hot paths - no product launch blocked by parameter
  lookup latency.

## 8. Dependencies & Reliance on Other Services

| Relies on | For |
|---|---|
| Sentin8:Auth | Verifying every token; certificate identity (CERTFREE-4V) for machine calls |
| Sentin8:Policy (Shield) | The authorization decision on every request |
| Sentin8:Bus | Durable delivery of all 30 outbound event types |
| Sentin8:Cron | Deciding *when* due schedules run (proxy-back execution) |
| Sentin8:Func | Executing tenant-authored hooks referenced by schedule contracts |
| Sentin8:Flow | Orchestrating statement regeneration with per-account retry |
| Sentin8:Storage | Storing generated statement documents |
| Sentin8:Stat | Metric ingest / telemetry |
| Sentin8:Sys | Service enablement events; central audit ingest via the journal pusher |
| Sentin8:BFF | All client traffic (`/proxy/ledger/*`) - tokens never reach the client |
| Bank8:Payments (peer) | Consumes ledger events; calls back for financial movement - the ledger is the only writer of balances |

## 9. Acceptance Criteria

1. A posting batch that does not balance is rejected with HTTP 422 and
   leaves no rows behind.
2. Retrying a committed posting with the same idempotency key returns the
   original result; balances change once.
3. A crash between any two internal steps of a posting leaves no partial
   state (atomic rollback).
4. An account cannot be opened against an inactive product.
5. A closed account cannot be reopened or posted to.
6. Effective parameter values follow global → product → account
   precedence, verified for arbitrary accounts/dates.
7. A failed scheduled job can be retried from the admin console and
   completes on retry; a DLQ entry can be replayed.
8. Statement documents exist in storage for every (account, period) after
   the scheduled run; regeneration is idempotent per (account, period).
9. All tenant data is invisible to other tenants under row-level security;
   a request without a resolvable tenant context is rejected.
10. Every capability listed in §2 is operable through the dashboard admin
    pages and/or the BFF-proxied API - no operator ever needs direct
    database access.
11. Each event in §4 is emitted exactly once per domain change (at-least-once
    delivery with idempotent consumers tolerated by design).

## 10. Open Business Questions

- Which additional product validation modules (e.g. multi-currency
  sweeps, goal-based savings rules) are on the roadmap, and do any
  require contract-simulation extensions?
- Should statement regeneration be exposed to bank staff as a
  self-service action (currently workflow-internal)?
- Are per-tenant statement formats/branding variants in scope, or is a
  single canonical document format sufficient for the current design?
- What is the business tolerance for the local DLQ replay SLA (manual
  replay) vs. a fully automated retry policy for scheduled work?

---

**Design attribution:** bank8:ledger and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
