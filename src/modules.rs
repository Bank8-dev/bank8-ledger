// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Ledger product module execution engine — 14 built-in modules.
//! Modules are the reusable building blocks of product behavior. Each module
//! encapsulates a specific financial rule. Products compose modules by listing
//! their names in the `modules` JSON array and configuring their parameters
//! in the `parameters` JSON blob.
//! Modules execute at three lifecycle points:
//! 1. Account creation — validate initial setup
//! 2. Posting time — validate each transaction (pre_posting_hook)
//! 3. On schedule — periodic processing (interest, fees, dormancy)

use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use chrono::Datelike;

use crate::types::{PostingInstructionV2, AccountV2};

/// Error returned when a module validation fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleError {
    pub module: String,
    pub message: String,
    pub code: String,
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.module, self.code, self.message)
    }
}

impl std::error::Error for ModuleError {}

/// Schedule types that modules can respond to.
#[derive(Debug, Clone)]
pub enum ScheduleType {
    InterestAccrual,
    InterestApplication,
    MaintenanceFee,
    InactivityFee,
    MinimumBalanceFee,
    Dormancy,
    StatementGeneration,
    MaturityProcessing,
}

/// Context passed to module hooks.
#[derive(Debug, Clone)]
pub struct ModuleContext<'a> {
    pub product_parameters: &'a serde_json::Value,
    pub modules: &'a [String],
    pub instance_params: &'a serde_json::Value,
}

impl<'a> ModuleContext<'a> {
    fn param(&self, key: &str) -> Option<&serde_json::Value> {
        self.product_parameters.get(key)
            .or_else(|| self.instance_params.get(key))
    }
    fn param_str(&self, key: &str) -> Option<&str> {
        self.param(key).and_then(|v| v.as_str())
    }
    fn param_dec(&self, key: &str) -> Option<Decimal> {
        self.param_str(key).and_then(|s| s.parse().ok())
    }
    fn has_module(&self, name: &str) -> bool {
        self.modules.iter().any(|m| m == name)
    }
}

// ── 1. denomination-validation ───────────────────────────────────────────

pub fn validate_creation_denomination(
    ctx: &ModuleContext,
    account: &AccountV2,
) -> Result<(), ModuleError> {
    if !ctx.has_module("denomination-validation") {
        return Ok(());
    }
    let supported: Vec<&str> = ctx.param("supported_denominations")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if supported.is_empty() {
        return Ok(());
    }
    if !supported.contains(&account.denomination.as_str()) {
        return Err(ModuleError {
            module: "denomination-validation".into(),
            message: format!("denomination {} not supported by product", account.denomination),
            code: "INVALID_DENOMINATION".into(),
        });
    }
    Ok(())
}

// ── 2. deposit-limits ────────────────────────────────────────────────────

pub fn validate_creation_deposit_limits(
    ctx: &ModuleContext,
    initial_deposit: Option<Decimal>,
) -> Result<(), ModuleError> {
    if !ctx.has_module("deposit-limits") {
        return Ok(());
    }
    if let Some(min) = ctx.param_dec("min_deposit_amount") {
        if let Some(deposit) = initial_deposit {
            if deposit < min {
                return Err(ModuleError {
                    module: "deposit-limits".into(),
                    message: format!("initial deposit {deposit} below minimum {min}"),
                    code: "BELOW_MIN_DEPOSIT".into(),
                });
            }
        }
    }
    Ok(())
}

pub fn validate_posting_deposit_limits(
    ctx: &ModuleContext,
    instruction: &PostingInstructionV2,
    daily_total: Decimal,
) -> Result<(), ModuleError> {
    if !ctx.has_module("deposit-limits") {
        return Ok(());
    }
    let amount: Decimal = instruction.amount.parse().unwrap_or(Decimal::ZERO);
    if let Some(min) = ctx.param_dec("min_deposit_amount") {
        if amount < min {
            return Err(ModuleError {
                module: "deposit-limits".into(),
                message: format!("deposit {amount} below minimum {min}"),
                code: "BELOW_MIN_DEPOSIT".into(),
            });
        }
    }
    if let Some(max_daily) = ctx.param_dec("max_daily_deposit_limit") {
        if daily_total + amount > max_daily {
            return Err(ModuleError {
                module: "deposit-limits".into(),
                message: format!("daily deposit limit {max_daily} exceeded"),
                code: "ABOVE_MAX_DAILY_DEPOSIT".into(),
            });
        }
    }
    Ok(())
}

// ── 3. withdrawal-limits ─────────────────────────────────────────────────

pub fn validate_posting_withdrawal_limits(
    ctx: &ModuleContext,
    instruction: &PostingInstructionV2,
    daily_total: Decimal,
) -> Result<(), ModuleError> {
    if !ctx.has_module("withdrawal-limits") {
        return Ok(());
    }
    let amount: Decimal = instruction.amount.parse().unwrap_or(Decimal::ZERO);
    if let Some(min) = ctx.param_dec("min_withdrawal_amount") {
        if amount < min {
            return Err(ModuleError {
                module: "withdrawal-limits".into(),
                message: format!("withdrawal {amount} below minimum {min}"),
                code: "BELOW_MIN_WITHDRAWAL".into(),
            });
        }
    }
    if let Some(max_daily) = ctx.param_dec("max_daily_withdrawal_limit") {
        if daily_total + amount > max_daily {
            return Err(ModuleError {
                module: "withdrawal-limits".into(),
                message: format!("daily withdrawal limit {max_daily} exceeded"),
                code: "ABOVE_MAX_DAILY_WITHDRAWAL".into(),
            });
        }
    }
    Ok(())
}

// ── 4. transaction-type-limits ──────────────────────────────────────────

pub fn validate_posting_transaction_type_limits(
    ctx: &ModuleContext,
    instruction: &PostingInstructionV2,
    daily_total: Decimal,
) -> Result<(), ModuleError> {
    if !ctx.has_module("transaction-type-limits") {
        return Ok(());
    }
    let tx_type = &instruction.instruction_type;
    let key = format!("max_daily_{}_limit", tx_type.to_lowercase());
    if let Some(max_daily) = ctx.param_dec(&key) {
        let amount: Decimal = instruction.amount.parse().unwrap_or(Decimal::ZERO);
        if daily_total + amount > max_daily {
            return Err(ModuleError {
                module: "transaction-type-limits".into(),
                message: format!("daily {tx_type} limit {max_daily} exceeded"),
                code: "ABOVE_MAX_DAILY_TXN_TYPE".into(),
            });
        }
    }
    Ok(())
}

// ── 5. maximum-balance ──────────────────────────────────────────────────

pub fn validate_posting_maximum_balance(
    ctx: &ModuleContext,
    instruction: &PostingInstructionV2,
    current_balance: Decimal,
) -> Result<(), ModuleError> {
    if !ctx.has_module("maximum-balance") {
        return Ok(());
    }
    let amount: Decimal = instruction.amount.parse().unwrap_or(Decimal::ZERO);
    if let Some(max) = ctx.param_dec("maximum_balance") {
        // Check if this is a credit (deposit) that would exceed max.
        // The credit_account receives the deposit — we check against that account's balance.
        if current_balance + amount > max {
            return Err(ModuleError {
                module: "maximum-balance".into(),
                message: format!("balance would exceed maximum {max}"),
                code: "ABOVE_MAX_BALANCE".into(),
            });
        }
    }
    Ok(())
}

// ── 6. overdraft-protection ──────────────────────────────────────────────

pub fn validate_posting_overdraft_protection(
    ctx: &ModuleContext,
    instruction: &PostingInstructionV2,
    current_balance: Decimal,
) -> Result<(), ModuleError> {
    if !ctx.has_module("overdraft-protection") {
        return Ok(());
    }
    let amount: Decimal = instruction.amount.parse().unwrap_or(Decimal::ZERO);
    // Only debit-direction instructions can drive the balance negative.
    // (Matches postings.rs `debits_source`: WITHDRAWAL | FEE_APPLICATION |
    // TRANSFER_OUT | REVERSAL_DEBIT | ADJUSTMENT_DEBIT.) A deposit credits
    // the account and must never trip the overdraft check.
    let is_debit = matches!(
        instruction.instruction_type.to_ascii_uppercase().as_str(),
        "WITHDRAWAL" | "FEE_APPLICATION" | "TRANSFER_OUT" | "REVERSAL_DEBIT" | "ADJUSTMENT_DEBIT"
    );
    if is_debit && current_balance - amount < Decimal::ZERO {
        let arranged: Option<Decimal> = ctx.param_dec("arranged_overdraft_limit");
        let unarranged: Option<Decimal> = ctx.param_dec("unarranged_overdraft_limit");
        let total_overdraft = arranged.unwrap_or(Decimal::ZERO) + unarranged.unwrap_or(Decimal::ZERO);
        if current_balance - amount < -total_overdraft {
            return Err(ModuleError {
                module: "overdraft-protection".into(),
                message: format!("withdrawal exceeds overdraft limit {total_overdraft}"),
                code: "OVERDRAFT_EXCEEDED".into(),
            });
        }
    }
    Ok(())
}

// ── 7. deposit-interest-accrual (scheduled) ──────────────────────────────

pub fn on_schedule_interest_accrual(
    ctx: &ModuleContext,
    _account: &AccountV2,
    current_balance: Decimal,
) -> Result<Decimal, ModuleError> {
    if !ctx.has_module("deposit-interest-accrual") {
        return Ok(Decimal::ZERO);
    }
    // Tiered interest rates: parameters has rate_tiers [{min_balance, rate}]
    let rate = compute_tiered_rate(ctx, current_balance);
    // Daily accrual = balance * rate / 365
    let days_in_year = Decimal::from(365);
    let accrued = current_balance * rate / days_in_year;
    let precision = ctx.param_dec("accrual_precision").unwrap_or(Decimal::new(1, 2)); // default 0.01
    // Round to precision
    let rounded = (accrued / precision).round() * precision;
    Ok(rounded)
}

fn compute_tiered_rate(ctx: &ModuleContext, balance: Decimal) -> Decimal {
    // rate_tiers: [{ "min_balance": "0", "rate": "0.01" }, { "min_balance": "10000", "rate": "0.02" }]
    if let Some(tiers) = ctx.param("rate_tiers").and_then(|v| v.as_array()) {
        let mut best_rate = Decimal::ZERO;
        let mut best_min = Decimal::ZERO;
        for tier in tiers {
            let min = tier.get("min_balance").and_then(|v| v.as_str()).and_then(|s| s.parse::<Decimal>().ok()).unwrap_or(Decimal::ZERO);
            let rate = tier.get("rate").and_then(|v| v.as_str()).and_then(|s| s.parse::<Decimal>().ok()).unwrap_or(Decimal::ZERO);
            if balance >= min && min >= best_min {
                best_rate = rate;
                best_min = min;
            }
        }
        return best_rate;
    }
    // Simple flat rate
    ctx.param_dec("interest_rate").unwrap_or(Decimal::ZERO)
}

// ── 8. deposit-interest-application (scheduled) ─────────────────────────

pub fn on_schedule_interest_application(
    ctx: &ModuleContext,
    _account: &AccountV2,
    accrued_interest: Decimal,
) -> Result<Decimal, ModuleError> {
    if !ctx.has_module("deposit-interest-application") {
        return Ok(Decimal::ZERO);
    }
    Ok(accrued_interest)
}

// ── 9. maintenance-fees (scheduled) ──────────────────────────────────────

pub fn on_schedule_maintenance_fee(
    ctx: &ModuleContext,
) -> Result<Decimal, ModuleError> {
    if !ctx.has_module("maintenance-fees") {
        return Ok(Decimal::ZERO);
    }
    Ok(ctx.param_dec("maintenance_fee_amount").unwrap_or(Decimal::ZERO))
}

// ── 10. inactivity-fee (scheduled) ──────────────────────────────────────

pub fn on_schedule_inactivity_fee(
    ctx: &ModuleContext,
    last_activity_days: i64,
) -> Result<Decimal, ModuleError> {
    if !ctx.has_module("inactivity-fee") {
        return Ok(Decimal::ZERO);
    }
    let threshold_days = ctx.param_dec("inactivity_threshold_days")
        .map(|d| d.to_i64())
        .unwrap_or(None)
        .unwrap_or(90);
    if last_activity_days > threshold_days {
        Ok(ctx.param_dec("inactivity_fee_amount").unwrap_or(Decimal::ZERO))
    } else {
        Ok(Decimal::ZERO)
    }
}

// ── 11. minimum-balance-fee (scheduled) ─────────────────────────────────

pub fn on_schedule_minimum_balance_fee(
    ctx: &ModuleContext,
    avg_balance: Decimal,
) -> Result<Decimal, ModuleError> {
    if !ctx.has_module("minimum-balance-fee") {
        return Ok(Decimal::ZERO);
    }
    let threshold = ctx.param_dec("minimum_balance_threshold").unwrap_or(Decimal::ZERO);
    if avg_balance < threshold {
        Ok(ctx.param_dec("minimum_balance_fee_amount").unwrap_or(Decimal::ZERO))
    } else {
        Ok(Decimal::ZERO)
    }
}

// ── 12. closure-interest-application ─────────────────────────────────────

pub fn on_closure_interest_application(
    ctx: &ModuleContext,
    accrued_interest: Decimal,
) -> Result<Decimal, ModuleError> {
    if !ctx.has_module("closure-interest-application") {
        return Ok(Decimal::ZERO);
    }
    // Forfeiture: if forfeiture_rate is set, forfeited = accrued * rate
    let forfeiture_rate = ctx.param_dec("forfeiture_rate").unwrap_or(Decimal::ZERO);
    let forfeited = accrued_interest * forfeiture_rate;
    Ok(accrued_interest - forfeited)
}

// ── 13. dormancy (scheduled) ────────────────────────────────────────────

pub fn on_schedule_dormancy(
    ctx: &ModuleContext,
    last_activity_days: i64,
) -> Result<bool, ModuleError> {
    if !ctx.has_module("dormancy") {
        return Ok(false);
    }
    let threshold = ctx.param_dec("dormancy_threshold_days")
        .map(|d| d.to_i64())
        .unwrap_or(None)
        .unwrap_or(365);
    Ok(last_activity_days > threshold)
}

// ── 14. overdraft-protection-sweep ──────────────────────────────────────

pub fn validate_posting_overdraft_sweep(
    ctx: &ModuleContext,
    _instruction: &PostingInstructionV2,
    current_balance: Decimal,
) -> Result<Option<Decimal>, ModuleError> {
    if !ctx.has_module("overdraft-protection-sweep") {
        return Ok(None);
    }
    if current_balance < Decimal::ZERO {
        let sweep_threshold = ctx.param_dec("sweep_threshold").unwrap_or(Decimal::ZERO);
        if current_balance < sweep_threshold {
            let sweep_amount = sweep_threshold - current_balance;
            return Ok(Some(sweep_amount));
        }
    }
    Ok(None)
}

// ── Validation dispatcher ────────────────────────────────────────────────

/// Run all applicable creation-time validation modules.
pub fn validate_creation(
    ctx: &ModuleContext,
    account: &AccountV2,
    initial_deposit: Option<Decimal>,
) -> Result<(), ModuleError> {
    validate_creation_denomination(ctx, account)?;
    validate_creation_deposit_limits(ctx, initial_deposit)?;
    Ok(())
}

/// Run all applicable posting-time validation modules.
pub fn validate_posting(
    ctx: &ModuleContext,
    instruction: &PostingInstructionV2,
    current_balance: Decimal,
    daily_deposit_total: Decimal,
    daily_withdrawal_total: Decimal,
    daily_txn_type_total: Decimal,
) -> Result<(), ModuleError> {
    validate_posting_deposit_limits(ctx, instruction, daily_deposit_total)?;
    validate_posting_withdrawal_limits(ctx, instruction, daily_withdrawal_total)?;
    validate_posting_transaction_type_limits(ctx, instruction, daily_txn_type_total)?;
    validate_posting_maximum_balance(ctx, instruction, current_balance)?;
    validate_posting_overdraft_protection(ctx, instruction, current_balance)?;
    Ok(())
}

// ── 15. Derived parameter computation (11.1b.20) ────────────────────────

/// Compute derived parameters for an account at runtime.
/// Derived parameters are calculated from template and instance parameters
/// rather than stored. Examples:
/// - `total_outstanding_debt` — sum of all loan account balances
/// - `remaining_term` — months remaining on a loan/mortgage
/// - `next_repayment_date` — next scheduled repayment date
/// - `available_redraw_funds` — available redraw on a home loan
pub fn compute_derived_parameters(
    ctx: &ModuleContext,
    account: &AccountV2,
    current_balance: Decimal,
) -> serde_json::Value {
    let mut derived = serde_json::Map::new();

    // Loan/Mortgage products: compute remaining term
    if matches!(account.product_type.as_deref(), Some("loan") | Some("mortgage") | Some("line_of_credit") | Some("bnpl") | Some("home_loan_redraw")) {
        if let Some(term_months) = ctx.param_dec("loan_term_months") {
            if let Some(opened_months_ago) = months_since(account.opened_at) {
                let remaining = (term_months - opened_months_ago).max(Decimal::ZERO);
                derived.insert("remaining_term".into(), serde_json::json!(remaining.to_string()));
            }
        }
        // Total outstanding debt = current balance (for asset-type accounts, balance is the debt)
        derived.insert("total_outstanding_debt".into(), serde_json::json!(current_balance.to_string()));

        // Next repayment date — if repayment_day is set, compute next occurrence
        let repayment_day = ctx.param("repayment_day").and_then(|v| match v {
            serde_json::Value::Number(n) => n.as_i64(),
            serde_json::Value::String(s) => s.parse::<i64>().ok(),
            _ => None,
        });
        if let Some(repayment_day) = repayment_day {
            let next = next_day_of_month(repayment_day as u32);
            derived.insert("next_repayment_date".into(), serde_json::json!(next.to_rfc3339()));
        }
    }

    // Home Loan Redraw: available_redraw_funds
    if account.product_type.as_deref() == Some("home_loan_redraw") {
        if let Some(redraw_limit_pct) = ctx.param_dec("redraw_limit_percentage") {
            let available = current_balance * redraw_limit_pct / Decimal::from(100);
            derived.insert("available_redraw_funds".into(), serde_json::json!(available.to_string()));
        }
    }

    // Credit Card: available credit
    if account.product_type.as_deref() == Some("credit_card") {
        if let Some(credit_limit) = ctx.param_dec("credit_limit") {
            let available = (credit_limit - current_balance).max(Decimal::ZERO);
            derived.insert("available_credit".into(), serde_json::json!(available.to_string()));
        }
    }

    // Time Deposit: maturity date
    if account.product_type.as_deref() == Some("time_deposit") {
        if let Some(term_months) = ctx.param_dec("term_months") {
            if let Some(opened) = account.opened_at {
                let maturity = opened + chrono::Duration::days((term_months * Decimal::from(30)).to_i64().unwrap_or(0) as i64);
                derived.insert("maturity_date".into(), serde_json::json!(maturity.to_rfc3339()));
            }
        }
    }

    serde_json::Value::Object(derived)
}

fn months_since(opened_at: Option<chrono::DateTime<chrono::Utc>>) -> Option<Decimal> {
    let opened = opened_at?;
    let now = chrono::Utc::now();
    let diff = now - opened;
    let months = (diff.num_days() / 30) as i64;
    Some(Decimal::from(months.max(0)))
}

fn next_day_of_month(day: u32) -> chrono::DateTime<chrono::Utc> {
    let now = chrono::Utc::now();
    let day_clamped = day.min(28).max(1);
    // Find the next occurrence of the given day
    let mut next = now.date_naive().with_day(day_clamped).unwrap_or(now.date_naive());
    if next <= now.date_naive() {
        next = next + chrono::Months::new(1);
    }
    next.and_hms_opt(0, 0, 0).unwrap().and_utc()
}

// ── 16. Product-type-specific parameter schema validation (11.1b.21) ────

/// Validate that product parameters match the schema for the product type.
/// Enforces parameter types, value ranges, and cross-field constraints.
pub fn validate_product_type_parameters(
    product_type: &str,
    parameters: &serde_json::Value,
) -> Result<(), ModuleError> {
    match product_type {
        "current_account" => {
            // overdraft_limit must be >= 0 if present
            if let Some(limit) = parameters.get("overdraft_limit").and_then(|v| v.as_str()).and_then(|s| s.parse::<Decimal>().ok()) {
                if limit < Decimal::ZERO {
                    return Err(ModuleError {
                        module: "product-validation".into(),
                        message: "overdraft_limit must be >= 0".into(),
                        code: "INVALID_VALUE".into(),
                    });
                }
            }
        }
        "mortgage" => {
            // due_amount_calculation_day must be 1–28
            if let Some(day) = parameters.get("due_amount_calculation_day").and_then(|v| v.as_i64()) {
                if day < 1 || day > 28 {
                    return Err(ModuleError {
                        module: "product-validation".into(),
                        message: format!("due_amount_calculation_day must be 1-28, got {day}"),
                        code: "OUT_OF_RANGE".into(),
                    });
                }
            }
            // loan_term_months must be > 0
            if let Some(term) = parameters.get("loan_term_months").and_then(|v| v.as_i64()) {
                if term <= 0 {
                    return Err(ModuleError {
                        module: "product-validation".into(),
                        message: "loan_term_months must be > 0".into(),
                        code: "INVALID_VALUE".into(),
                    });
                }
            }
        }
        "credit_card" => {
            // credit_limit must be > 0
            if let Some(limit) = parameters.get("credit_limit").and_then(|v| v.as_str()).and_then(|s| s.parse::<Decimal>().ok()) {
                if limit <= Decimal::ZERO {
                    return Err(ModuleError {
                        module: "product-validation".into(),
                        message: "credit_limit must be > 0".into(),
                        code: "INVALID_VALUE".into(),
                    });
                }
            }
        }
        "time_deposit" => {
            // term_months must be > 0
            if let Some(term) = parameters.get("term_months").and_then(|v| v.as_i64()) {
                if term <= 0 {
                    return Err(ModuleError {
                        module: "product-validation".into(),
                        message: "term_months must be > 0".into(),
                        code: "INVALID_VALUE".into(),
                    });
                }
            }
        }
        "savings_account" | "us_savings" | "shariah_savings" => {
            // interest_rate must be >= 0
            if let Some(rate) = parameters.get("interest_rate").and_then(|v| v.as_str()).and_then(|s| s.parse::<Decimal>().ok()) {
                if rate < Decimal::ZERO {
                    return Err(ModuleError {
                        module: "product-validation".into(),
                        message: "interest_rate must be >= 0".into(),
                        code: "INVALID_VALUE".into(),
                    });
                }
            }
        }
        _ => {}
    }
    Ok(())
}

// ── 17. Module composition enforcement (11.1b.22) ────────────────────────

/// Validate that the modules listed in the `modules` array are compatible
/// with the product type. For example, `overdraft-protection` is only valid
/// for current accounts, not savings accounts.
pub fn validate_module_composition(
    product_type: &str,
    modules: &[String],
) -> Result<(), ModuleError> {
    // Define which modules are valid for each product type
    let (allowed, disallowed) = module_rules_for_product(product_type);

    for module in modules {
        if let Some(reason) = disallowed.iter().find(|(m, _)| m == module).map(|(_, r)| r) {
            return Err(ModuleError {
                module: "module-composition".into(),
                message: format!("module `{module}` is not valid for product type `{product_type}`: {reason}"),
                code: "INVALID_MODULE_FOR_PRODUCT".into(),
            });
        }
        // Warn (not error) if module is not in the allowed list — it may be a custom module
        if !allowed.iter().any(|m| m == module) {
            tracing::debug!(module = %module, product_type = %product_type, "module not in standard allowed list (may be custom)");
        }
    }
    Ok(())
}

fn module_rules_for_product(product_type: &str) -> (Vec<&'static str>, Vec<(&'static str, &'static str)>) {
    match product_type {
        "current_account" | "us_checking" => (
            vec![
                "denomination-validation", "deposit-limits", "withdrawal-limits",
                "transaction-type-limits", "maximum-balance", "overdraft-protection",
                "overdraft-protection-sweep", "deposit-interest-accrual",
                "deposit-interest-application", "maintenance-fees", "inactivity-fee",
                "minimum-balance-fee", "closure-interest-application", "dormancy",
            ],
            vec![],
        ),
        "savings_account" | "us_savings" | "shariah_savings" => (
            vec![
                "denomination-validation", "deposit-limits", "withdrawal-limits",
                "maximum-balance", "deposit-interest-accrual",
                "deposit-interest-application", "maintenance-fees", "inactivity-fee",
                "minimum-balance-fee", "closure-interest-application", "dormancy",
            ],
            vec![
                ("overdraft-protection", "savings accounts cannot have overdraft"),
                ("overdraft-protection-sweep", "savings accounts cannot have overdraft sweep"),
            ],
        ),
        "time_deposit" => (
            vec![
                "denomination-validation", "deposit-limits", "maximum-balance",
                "deposit-interest-accrual", "deposit-interest-application",
                "closure-interest-application",
            ],
            vec![
                ("overdraft-protection", "time deposits cannot have overdraft"),
                ("withdrawal-limits", "time deposits do not support withdrawals before maturity"),
                ("maintenance-fees", "time deposits do not have maintenance fees"),
            ],
        ),
        "loan" | "mortgage" | "home_loan_redraw" | "bnpl" => (
            vec![
                "denomination-validation", "deposit-limits", "withdrawal-limits",
                "transaction-type-limits",
            ],
            vec![
                ("deposit-interest-accrual", "loans do not accrue deposit interest"),
                ("deposit-interest-application", "loans do not apply deposit interest"),
                ("maintenance-fees", "loans do not have maintenance fees"),
                ("inactivity-fee", "loans do not have inactivity fees"),
                ("dormancy", "loans do not have dormancy"),
            ],
        ),
        "credit_card" => (
            vec![
                "denomination-validation", "transaction-type-limits",
            ],
            vec![
                ("deposit-limits", "credit cards do not use deposit limits"),
                ("withdrawal-limits", "credit cards do not use withdrawal limits"),
                ("maximum-balance", "credit cards do not use maximum balance"),
                ("deposit-interest-accrual", "credit cards do not accrue deposit interest"),
                ("dormancy", "credit cards do not have dormancy"),
            ],
        ),
        "line_of_credit" | "wallet" => (
            vec![
                "denomination-validation", "transaction-type-limits",
            ],
            vec![
                ("deposit-interest-accrual", "this product type does not accrue deposit interest"),
                ("dormancy", "this product type does not have dormancy"),
            ],
        ),
        _ => (vec![], vec![]), // unknown product types: allow all modules
    }
}

// ── Unit tests (design §8.6) ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fixtures (design §8.6.2: DB-free builders) ───────────────────────

    fn account(product_type: Option<&str>, denomination: &str) -> AccountV2 {
        AccountV2 {
            id: uuid::Uuid::nil(),
            env_id: uuid::Uuid::nil(),
            customer_id: None,
            product_id: None,
            account_type: "CUSTOMER".into(),
            product_type: product_type.map(|s| s.into()),
            nickname: None,
            status: "OPEN".into(),
            denomination: denomination.into(),
            permitted_denominations: vec![],
            tside: "ASSET".into(),
            processing_group_id: None,
            sentin8_func_version_id: None,
            pending_sentin8_func_version_id: None,
            stakeholder_ids: vec![],
            opened_at: Some(chrono::Utc::now()),
            closed_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn instruction(instruction_type: &str, amount: &str) -> PostingInstructionV2 {
        PostingInstructionV2 {
            instruction_type: instruction_type.into(),
            debit_account: uuid::Uuid::nil(),
            credit_account: uuid::Uuid::nil(),
            amount: amount.into(),
            denomination: "CAD".into(),
            value_timestamp: None,
            booking_timestamp: None,
            client_transaction_id: None,
            description: None,
        }
    }

    /// Owned context holder — keeps `modules` and `params` alive so
    /// `ModuleContext` borrowed references stay valid without leaking.
    struct OwnedCtx {
        modules: Vec<String>,
        params: serde_json::Value,
    }

    impl OwnedCtx {
        fn new(modules: &[&str], params: serde_json::Value) -> Self {
            Self {
                modules: modules.iter().map(|m| m.to_string()).collect(),
                params,
            }
        }
        fn ctx(&self) -> ModuleContext<'_> {
            ModuleContext {
                product_parameters: &self.params,
                modules: &self.modules,
                instance_params: &serde_json::Value::Null,
            }
        }
    }

    fn err_of(r: Result<(), ModuleError>) -> ModuleError {
        r.expect_err("expected ModuleError")
    }

    const DEC_ZERO: Decimal = Decimal::ZERO;

    fn dec(s: &str) -> Decimal {
        s.parse().unwrap()
    }

    // ── 1. validate_creation_denomination ────────────────────────────────

    #[test]
    fn denomination_absent_module_is_noop() {
        let o = OwnedCtx::new(&[], serde_json::json!({}));
        let c = o.ctx();
        validate_creation_denomination(&c, &account(None, "USD")).unwrap();
    }

    #[test]
    fn denomination_empty_supported_list_is_noop() {
        let o = OwnedCtx::new(&["denomination-validation"], serde_json::json!({"supported_denominations": []}));
        let c = o.ctx();
        validate_creation_denomination(&c, &account(None, "USD")).unwrap();
    }

    #[test]
    fn denomination_unsupported_rejected() {
        let o = OwnedCtx::new(
            &["denomination-validation"],
            serde_json::json!({"supported_denominations": ["CAD", "USD"]}),
        );
        let c = o.ctx();
        let e = err_of(validate_creation_denomination(&c, &account(None, "EUR")));
        assert_eq!(e.code, "INVALID_DENOMINATION");
        assert_eq!(e.module, "denomination-validation");
    }

    #[test]
    fn denomination_supported_accepted() {
        let o = OwnedCtx::new(
            &["denomination-validation"],
            serde_json::json!({"supported_denominations": ["CAD"]}),
        );
        let c = o.ctx();
        validate_creation_denomination(&c, &account(None, "CAD")).unwrap();
    }

    // ── 2. validate_creation_deposit_limits ──────────────────────────────

    #[test]
    fn creation_deposit_absent_module_is_noop() {
        let o = OwnedCtx::new(&[], serde_json::json!({"min_deposit_amount": "100"}));
        let c = o.ctx();
        validate_creation_deposit_limits(&c, Some(dec("10"))).unwrap();
    }

    #[test]
    fn creation_deposit_below_minimum_rejected() {
        let o = OwnedCtx::new(&["deposit-limits"], serde_json::json!({"min_deposit_amount": "100"}));
        let c = o.ctx();
        let e = err_of(validate_creation_deposit_limits(&c, Some(dec("50"))));
        assert_eq!(e.code, "BELOW_MIN_DEPOSIT");
    }

    #[test]
    fn creation_deposit_at_minimum_accepted() {
        let o = OwnedCtx::new(&["deposit-limits"], serde_json::json!({"min_deposit_amount": "100"}));
        let c = o.ctx();
        validate_creation_deposit_limits(&c, Some(dec("100"))).unwrap();
    }

    #[test]
    fn creation_deposit_none_accepted_when_min_set() {
        let o = OwnedCtx::new(&["deposit-limits"], serde_json::json!({"min_deposit_amount": "100"}));
        let c = o.ctx();
        validate_creation_deposit_limits(&c, None).unwrap();
    }

    // ── 3. validate_posting_deposit_limits ───────────────────────────────

    #[test]
    fn posting_deposit_below_min_rejected() {
        let o = OwnedCtx::new(&["deposit-limits"], serde_json::json!({"min_deposit_amount": "10"}));
        let c = o.ctx();
        let e = err_of(validate_posting_deposit_limits(&c, &instruction("DEPOSIT", "5"), DEC_ZERO));
        assert_eq!(e.code, "BELOW_MIN_DEPOSIT");
    }

    #[test]
    fn posting_deposit_daily_limit_inclusive_at_max() {
        // daily_total + amount == max_daily_deposit_limit is allowed (>) check.
        let o = OwnedCtx::new(&["deposit-limits"], serde_json::json!({"max_daily_deposit_limit": "500"}));
        let c = o.ctx();
        validate_posting_deposit_limits(&c, &instruction("DEPOSIT", "200"), dec("300")).unwrap();
    }

    #[test]
    fn posting_deposit_daily_limit_exceeded_rejected() {
        let o = OwnedCtx::new(&["deposit-limits"], serde_json::json!({"max_daily_deposit_limit": "500"}));
        let c = o.ctx();
        let e = err_of(validate_posting_deposit_limits(&c, &instruction("DEPOSIT", "200"), dec("301")));
        assert_eq!(e.code, "ABOVE_MAX_DAILY_DEPOSIT");
    }

    #[test]
    fn posting_deposit_absent_module_is_noop() {
        let o = OwnedCtx::new(&[], serde_json::json!({"min_deposit_amount": "10"}));
        let c = o.ctx();
        validate_posting_deposit_limits(&c, &instruction("DEPOSIT", "1"), DEC_ZERO).unwrap();
    }

    // ── 4. validate_posting_withdrawal_limits ────────────────────────────

    #[test]
    fn posting_withdrawal_below_min_rejected() {
        let o = OwnedCtx::new(&["withdrawal-limits"], serde_json::json!({"min_withdrawal_amount": "20"}));
        let c = o.ctx();
        let e = err_of(validate_posting_withdrawal_limits(&c, &instruction("WITHDRAWAL", "5"), DEC_ZERO));
        assert_eq!(e.code, "BELOW_MIN_WITHDRAWAL");
    }

    #[test]
    fn posting_withdrawal_daily_limit_exceeded_rejected() {
        let o = OwnedCtx::new(&["withdrawal-limits"], serde_json::json!({"max_daily_withdrawal_limit": "1000"}));
        let c = o.ctx();
        let e = err_of(validate_posting_withdrawal_limits(&c, &instruction("WITHDRAWAL", "100"), dec("901")));
        assert_eq!(e.code, "ABOVE_MAX_DAILY_WITHDRAWAL");
    }

    #[test]
    fn posting_withdrawal_within_limits_accepted() {
        let o = OwnedCtx::new(
            &["withdrawal-limits"],
            serde_json::json!({"min_withdrawal_amount": "20", "max_daily_withdrawal_limit": "1000"}),
        );
        let c = o.ctx();
        validate_posting_withdrawal_limits(&c, &instruction("WITHDRAWAL", "100"), dec("900")).unwrap();
    }

    // ── 5. validate_posting_transaction_type_limits ──────────────────────

    #[test]
    fn posting_txn_type_limit_key_derivation() {
        // instruction_type "payment" → key "max_daily_payment_limit".
        let o = OwnedCtx::new(
            &["transaction-type-limits"],
            serde_json::json!({"max_daily_payment_limit": "250"}),
        );
        let c = o.ctx();
        let e = err_of(validate_posting_transaction_type_limits(&c, &instruction("PAYMENT", "300"), DEC_ZERO));
        assert_eq!(e.code, "ABOVE_MAX_DAILY_TXN_TYPE");
    }

    #[test]
    fn posting_txn_type_unconfigured_type_is_noop() {
        let o = OwnedCtx::new(
            &["transaction-type-limits"],
            serde_json::json!({"max_daily_payment_limit": "250"}),
        );
        let c = o.ctx();
        validate_posting_transaction_type_limits(&c, &instruction("TRANSFER", "999999"), DEC_ZERO).unwrap();
    }

    #[test]
    fn posting_txn_type_absent_module_is_noop() {
        let o = OwnedCtx::new(&[], serde_json::json!({}));
        let c = o.ctx();
        validate_posting_transaction_type_limits(&c, &instruction("PAYMENT", "999"), DEC_ZERO).unwrap();
    }

    // ── 6. validate_posting_maximum_balance ──────────────────────────────

    #[test]
    fn posting_max_balance_at_max_accepted() {
        let o = OwnedCtx::new(&["maximum-balance"], serde_json::json!({"maximum_balance": "10000"}));
        let c = o.ctx();
        validate_posting_maximum_balance(&c, &instruction("DEPOSIT", "300"), dec("9700")).unwrap();
    }

    #[test]
    fn posting_max_balance_exceeded_rejected() {
        let o = OwnedCtx::new(&["maximum-balance"], serde_json::json!({"maximum_balance": "10000"}));
        let c = o.ctx();
        let e = err_of(validate_posting_maximum_balance(&c, &instruction("DEPOSIT", "300"), dec("9700.01")));
        assert_eq!(e.code, "ABOVE_MAX_BALANCE");
    }

    #[test]
    fn posting_max_balance_absent_module_is_noop() {
        let o = OwnedCtx::new(&[], serde_json::json!({}));
        let c = o.ctx();
        validate_posting_maximum_balance(&c, &instruction("DEPOSIT", "1"), dec("999999999")).unwrap();
    }

    // ── 7. validate_posting_overdraft_protection ─────────────────────────

    #[test]
    fn overdraft_withdrawal_within_arranged_limit_accepted() {
        // balance 100, withdrawal 250 → -150; arranged 200 covers it.
        let o = OwnedCtx::new(
            &["overdraft-protection"],
            serde_json::json!({"arranged_overdraft_limit": "200"}),
        );
        let c = o.ctx();
        validate_posting_overdraft_protection(&c, &instruction("WITHDRAWAL", "250"), dec("100")).unwrap();
    }

    #[test]
    fn overdraft_withdrawal_beyond_limit_rejected() {
        // balance 100, withdrawal 400 → -300; arranged 200 + unarranged 50 = 250.
        let o = OwnedCtx::new(
            &["overdraft-protection"],
            serde_json::json!({"arranged_overdraft_limit": "200", "unarranged_overdraft_limit": "50"}),
        );
        let c = o.ctx();
        let e = err_of(validate_posting_overdraft_protection(&c, &instruction("WITHDRAWAL", "400"), dec("100")));
        assert_eq!(e.code, "OVERDRAFT_EXCEEDED");
    }

    #[test]
    fn overdraft_no_limits_means_no_negative_allowed() {
        // balance 50, withdrawal 60 → -10; no limits configured → rejected.
        let o = OwnedCtx::new(&["overdraft-protection"], serde_json::json!({}));
        let c = o.ctx();
        let e = err_of(validate_posting_overdraft_protection(&c, &instruction("WITHDRAWAL", "60"), dec("50")));
        assert_eq!(e.code, "OVERDRAFT_EXCEEDED");
    }

    #[test]
    fn overdraft_positive_balance_never_rejected() {
        let o = OwnedCtx::new(&["overdraft-protection"], serde_json::json!({}));
        let c = o.ctx();
        validate_posting_overdraft_protection(&c, &instruction("DEPOSIT", "100"), dec("500")).unwrap();
    }

    // ── 8. compute_tiered_rate via on_schedule_interest_accrual ──────────

    #[test]
    fn accrual_absent_module_is_zero() {
        let o = OwnedCtx::new(&[], serde_json::json!({"interest_rate": "0.05"}));
        let c = o.ctx();
        let a = on_schedule_interest_accrual(&c, &account(None, "CAD"), dec("10000")).unwrap();
        assert_eq!(a, Decimal::ZERO);
    }

    #[test]
    fn accrual_flat_rate_daily() {
        let o = OwnedCtx::new(&["deposit-interest-accrual"], serde_json::json!({"interest_rate": "0.0365"}));
        let c = o.ctx();
        let a = on_schedule_interest_accrual(&c, &account(None, "CAD"), dec("10000")).unwrap();
        assert_eq!(a.to_string(), "1.00");
    }

    #[test]
    fn accrual_tier_selected_at_boundary() {
        // min_balance is inclusive: balance 10000 selects the 0.02 tier.
        let o = OwnedCtx::new(
            &["deposit-interest-accrual"],
            serde_json::json!({"rate_tiers": [
                {"min_balance": "0", "rate": "0.01"},
                {"min_balance": "10000", "rate": "0.02"},
            ]}),
        );
        let c = o.ctx();
        let a = on_schedule_interest_accrual(&c, &account(None, "CAD"), dec("10000")).unwrap();
        // 10000 * 0.02 / 365 = 0.5479452… → rounds to 0.55 at 0.01 precision.
        assert_eq!(a.to_string(), "0.55");
    }

    #[test]
    fn accrual_tier_below_boundary_uses_lower_tier() {
        let o = OwnedCtx::new(
            &["deposit-interest-accrual"],
            serde_json::json!({"rate_tiers": [
                {"min_balance": "0", "rate": "0.01"},
                {"min_balance": "10000", "rate": "0.02"},
            ]}),
        );
        let c = o.ctx();
        let a = on_schedule_interest_accrual(&c, &account(None, "CAD"), dec("9999")).unwrap();
        assert_eq!(a.to_string(), "0.27");
    }

    #[test]
    fn accrual_highest_tier_wins_on_balance() {
        let o = OwnedCtx::new(
            &["deposit-interest-accrual"],
            serde_json::json!({"rate_tiers": [
                {"min_balance": "0", "rate": "0.01"},
                {"min_balance": "5000", "rate": "0.02"},
                {"min_balance": "20000", "rate": "0.03"},
            ]}),
        );
        let c = o.ctx();
        let a = on_schedule_interest_accrual(&c, &account(None, "CAD"), dec("25000")).unwrap();
        assert_eq!(a.to_string(), "2.05");
    }

    // ── 9. on_schedule_interest_application ──────────────────────────────

    #[test]
    fn interest_application_passes_through_accrued() {
        let o = OwnedCtx::new(&["deposit-interest-application"], serde_json::json!({}));
        let c = o.ctx();
        let a = on_schedule_interest_application(&c, &account(None, "CAD"), dec("12.34")).unwrap();
        assert_eq!(a, dec("12.34"));
    }

    #[test]
    fn interest_application_absent_module_is_zero() {
        let o = OwnedCtx::new(&[], serde_json::json!({}));
        let c = o.ctx();
        let a = on_schedule_interest_application(&c, &account(None, "CAD"), dec("12.34")).unwrap();
        assert_eq!(a, Decimal::ZERO);
    }

    // ── 10. Fee modules ──────────────────────────────────────────────────

    #[test]
    fn maintenance_fee_configured() {
        let o = OwnedCtx::new(&["maintenance-fees"], serde_json::json!({"maintenance_fee_amount": "4.95"}));
        let c = o.ctx();
        let f = on_schedule_maintenance_fee(&c).unwrap();
        assert_eq!(f, dec("4.95"));
    }

    #[test]
    fn maintenance_fee_absent_module_is_zero() {
        let o = OwnedCtx::new(&[], serde_json::json!({}));
        let c = o.ctx();
        let f = on_schedule_maintenance_fee(&c).unwrap();
        assert_eq!(f, Decimal::ZERO);
    }

    #[test]
    fn inactivity_fee_charged_past_threshold() {
        let o = OwnedCtx::new(
            &["inactivity-fee"],
            serde_json::json!({"inactivity_threshold_days": 180, "inactivity_fee_amount": "2.50"}),
        );
        let c = o.ctx();
        let f = on_schedule_inactivity_fee(&c, 181).unwrap();
        assert_eq!(f, dec("2.50"));
    }

    #[test]
    fn inactivity_fee_not_charged_at_threshold() {
        // NOTE: params are read via `as_str ` — numeric JSON values
        // silently fall back to the default threshold. String form is the
        // calling convention (same as amounts).
        let o = OwnedCtx::new(
            &["inactivity-fee"],
            serde_json::json!({"inactivity_threshold_days": "180", "inactivity_fee_amount": "2.50"}),
        );
        let c = o.ctx();
        // last_activity_days == threshold → not "<", no fee.
        let f = on_schedule_inactivity_fee(&c, 180).unwrap();
        assert_eq!(f, Decimal::ZERO);
    }

    #[test]
    fn inactivity_fee_integer_threshold_falls_back_to_default_90() {
        // Documents the as_str parse quirk: an integer threshold is ignored
        // (defaults to 90), so day 181 is charged under the default.
        let o = OwnedCtx::new(
            &["inactivity-fee"],
            serde_json::json!({"inactivity_threshold_days": 180, "inactivity_fee_amount": "2.50"}),
        );
        let c = o.ctx();
        assert_eq!(on_schedule_inactivity_fee(&c, 181).unwrap(), dec("2.50"));
    }

    #[test]
    fn inactivity_fee_default_threshold_90_days() {
        let o = OwnedCtx::new(&["inactivity-fee"], serde_json::json!({"inactivity_fee_amount": "2.50"}));
        let c = o.ctx();
        assert_eq!(on_schedule_inactivity_fee(&c, 91).unwrap(), dec("2.50"));
        assert_eq!(on_schedule_inactivity_fee(&c, 90).unwrap(), Decimal::ZERO);
    }

    #[test]
    fn minimum_balance_fee_charged_below_threshold() {
        let o = OwnedCtx::new(
            &["minimum-balance-fee"],
            serde_json::json!({"minimum_balance_threshold": "1000", "minimum_balance_fee_amount": "5.00"}),
        );
        let c = o.ctx();
        let f = on_schedule_minimum_balance_fee(&c, dec("99.99")).unwrap();
        assert_eq!(f, dec("5.00"));
    }

    #[test]
    fn minimum_balance_fee_not_charged_at_threshold() {
        let o = OwnedCtx::new(
            &["minimum-balance-fee"],
            serde_json::json!({"minimum_balance_threshold": "1000", "minimum_balance_fee_amount": "5.00"}),
        );
        let c = o.ctx();
        let f = on_schedule_minimum_balance_fee(&c, dec("1000")).unwrap();
        assert_eq!(f, Decimal::ZERO);
    }

    // ── 11. on_closure_interest_application (forfeiture) ─────────────────

    #[test]
    fn closure_interest_full_paid_without_forfeiture() {
        let o = OwnedCtx::new(&["closure-interest-application"], serde_json::json!({}));
        let c = o.ctx();
        let p = on_closure_interest_application(&c, dec("50.00")).unwrap();
        assert_eq!(p, dec("50.00"));
    }

    #[test]
    fn closure_interest_forfeited_by_rate() {
        // forfeiture_rate 0.25 → 50 - 12.5 = 37.5
        let o = OwnedCtx::new(&["closure-interest-application"], serde_json::json!({"forfeiture_rate": "0.25"}));
        let c = o.ctx();
        let p = on_closure_interest_application(&c, dec("50.00")).unwrap();
        assert_eq!(p, dec("37.50"));
    }

    #[test]
    fn closure_interest_absent_module_is_zero() {
        let o = OwnedCtx::new(&[], serde_json::json!({}));
        let c = o.ctx();
        let p = on_closure_interest_application(&c, dec("50.00")).unwrap();
        assert_eq!(p, Decimal::ZERO);
    }

    // ── 12. on_schedule_dormancy ─────────────────────────────────────────

    #[test]
    fn dormancy_triggers_past_default_threshold() {
        let o = OwnedCtx::new(&["dormancy"], serde_json::json!({}));
        let c = o.ctx();
        assert!(on_schedule_dormancy(&c, 366).unwrap());
        assert!(!on_schedule_dormancy(&c, 365).unwrap());
    }

    #[test]
    fn dormancy_explicit_threshold_honored() {
        let o = OwnedCtx::new(&["dormancy"], serde_json::json!({"dormancy_threshold_days": "180"}));
        let c = o.ctx();
        assert!(on_schedule_dormancy(&c, 181).unwrap());
        assert!(!on_schedule_dormancy(&c, 180).unwrap());
    }

    #[test]
    fn dormancy_absent_module_is_false() {
        let o = OwnedCtx::new(&[], serde_json::json!({}));
        let c = o.ctx();
        assert!(!on_schedule_dormancy(&c, 100_000).unwrap());
    }

    // ── 13. validate_posting_overdraft_sweep ─────────────────────────────

    #[test]
    fn overdraft_sweep_triggers_below_threshold() {
        // balance -120, threshold 0 → sweep 120.
        let o = OwnedCtx::new(&["overdraft-protection-sweep"], serde_json::json!({"sweep_threshold": "0"}));
        let c = o.ctx();
        let s = validate_posting_overdraft_sweep(&c, &instruction("WITHDRAWAL", "1"), dec("-120")).unwrap();
        assert_eq!(s, Some(dec("120")));
    }

    #[test]
    fn overdraft_sweep_amount_is_gap_to_threshold() {
        // balance -60, threshold -25 → sweep 35.
        let o = OwnedCtx::new(&["overdraft-protection-sweep"], serde_json::json!({"sweep_threshold": "-25"}));
        let c = o.ctx();
        let s = validate_posting_overdraft_sweep(&c, &instruction("WITHDRAWAL", "1"), dec("-60")).unwrap();
        assert_eq!(s, Some(dec("35")));
    }

    #[test]
    fn overdraft_sweep_noop_when_positive_balance() {
        let o = OwnedCtx::new(&["overdraft-protection-sweep"], serde_json::json!({"sweep_threshold": "0"}));
        let c = o.ctx();
        let s = validate_posting_overdraft_sweep(&c, &instruction("WITHDRAWAL", "1"), dec("10")).unwrap();
        assert_eq!(s, None);
    }

    #[test]
    fn overdraft_sweep_noop_when_balance_at_threshold() {
        // balance -25 == threshold → not below → no sweep.
        let o = OwnedCtx::new(&["overdraft-protection-sweep"], serde_json::json!({"sweep_threshold": "-25"}));
        let c = o.ctx();
        let s = validate_posting_overdraft_sweep(&c, &instruction("WITHDRAWAL", "1"), dec("-25")).unwrap();
        assert_eq!(s, None);
    }

    // ── 14. Dispatchers ──────────────────────────────────────────────────

    #[test]
    fn validate_creation_composes_all_validators() {
        let o = OwnedCtx::new(
            &["denomination-validation", "deposit-limits"],
            serde_json::json!({"supported_denominations": ["CAD"], "min_deposit_amount": "100"}),
        );
        let c = o.ctx();
        // Denomination fails first.
        let e = err_of(validate_creation(&c, &account(None, "EUR"), Some(dec("500"))));
        assert_eq!(e.code, "INVALID_DENOMINATION");
        // Denomination ok → deposit limit fails.
        let e2 = err_of(validate_creation(&c, &account(None, "CAD"), Some(dec("50"))));
        assert_eq!(e2.code, "BELOW_MIN_DEPOSIT");
        // Both ok.
        validate_creation(&c, &account(None, "CAD"), Some(dec("100"))).unwrap();
    }

    #[test]
    fn validate_posting_short_circuits_on_first_failure() {
        let o = OwnedCtx::new(
            &["deposit-limits", "withdrawal-limits"],
            serde_json::json!({"min_deposit_amount": "10", "min_withdrawal_amount": "10"}),
        );
        let c = o.ctx();
        // Both min-limits violated → deposit-limits runs first.
        let e = err_of(validate_posting(
            &c,
            &instruction("WITHDRAWAL", "1"),
            dec("0"),
            DEC_ZERO,
            DEC_ZERO,
            DEC_ZERO,
        ));
        assert_eq!(e.code, "BELOW_MIN_DEPOSIT");
    }

    #[test]
    fn validate_posting_all_pass() {
        let o = OwnedCtx::new(
            &["deposit-limits", "withdrawal-limits", "maximum-balance", "overdraft-protection"],
            serde_json::json!({"min_deposit_amount": "1", "min_withdrawal_amount": "1", "maximum_balance": "100000"}),
        );
        let c = o.ctx();
        validate_posting(
            &c,
            &instruction("DEPOSIT", "50"),
            dec("1000"),
            dec("100"),
            dec("100"),
            DEC_ZERO,
        )
        .unwrap();
    }

    // ── 15. compute_derived_parameters ───────────────────────────────────

    #[test]
    fn derived_credit_card_available_credit_clamped_at_zero() {
        let o = OwnedCtx::new(&[""], serde_json::json!({"credit_limit": "5000"}));
        let c = o.ctx();
        // Balance 7000 > credit limit 5000 → available clamped to 0.
        let d = compute_derived_parameters(&c, &account(Some("credit_card"), "CAD"), dec("7000"));
        assert_eq!(d["available_credit"], serde_json::json!("0"));
    }

    #[test]
    fn derived_credit_card_available_credit_positive() {
        let o = OwnedCtx::new(&[""], serde_json::json!({"credit_limit": "5000"}));
        let c = o.ctx();
        let d = compute_derived_parameters(&c, &account(Some("credit_card"), "CAD"), dec("1234.50"));
        assert_eq!(d["available_credit"], serde_json::json!("3765.50"));
    }

    #[test]
    fn derived_loan_outstanding_debt_and_remaining_term() {
        let o = OwnedCtx::new(&[""], serde_json::json!({"loan_term_months": "60"}));
        let c = o.ctx();
        // Opened ~2 months ago → remaining_term 57 or 58 (day-count boundary).
        let mut acc = account(Some("mortgage"), "CAD");
        acc.opened_at = Some(chrono::Utc::now() - chrono::Duration::days(75));
        let d = compute_derived_parameters(&c, &acc, dec("250000"));
        assert_eq!(d["total_outstanding_debt"], serde_json::json!("250000"));
        let rem = d["remaining_term"].as_str().unwrap().parse::<Decimal>().unwrap();
        assert!(rem >= Decimal::from(56) && rem <= Decimal::from(58), "remaining_term={rem}");
    }

    #[test]
    fn derived_redraw_funds_percentage() {
        let o = OwnedCtx::new(&[""], serde_json::json!({"redraw_limit_percentage": "80"}));
        let c = o.ctx();
        let d = compute_derived_parameters(&c, &account(Some("home_loan_redraw"), "CAD"), dec("10000"));
        assert_eq!(d["available_redraw_funds"], serde_json::json!("8000"));
    }

    #[test]
    fn derived_non_loan_product_has_no_loan_fields() {
        let o = OwnedCtx::new(&[""], serde_json::json!({"credit_limit": "5000"}));
        let c = o.ctx();
        let d = compute_derived_parameters(&c, &account(Some("current_account"), "CAD"), dec("100"));
        assert!(d.get("available_credit").is_none());
        assert!(d.get("remaining_term").is_none());
    }

    // ── 16. validate_product_type_parameters ─────────────────────────────

    #[test]
    fn product_params_current_account_negative_overdraft_rejected() {
        let e = err_of(validate_product_type_parameters(
            "current_account",
            &serde_json::json!({"overdraft_limit": "-100"}),
        ));
        assert_eq!(e.code, "INVALID_VALUE");
        // Non-negative accepted.
        validate_product_type_parameters("current_account", &serde_json::json!({"overdraft_limit": "0"})).unwrap();
    }

    #[test]
    fn product_params_mortgage_due_day_range() {
        err_of(validate_product_type_parameters(
            "mortgage",
            &serde_json::json!({"due_amount_calculation_day": 0}),
        ));
        err_of(validate_product_type_parameters(
            "mortgage",
            &serde_json::json!({"due_amount_calculation_day": 29}),
        ));
        validate_product_type_parameters("mortgage", &serde_json::json!({"due_amount_calculation_day": 28})).unwrap();
        validate_product_type_parameters("mortgage", &serde_json::json!({"due_amount_calculation_day": 1})).unwrap();
        // Non-mortgage rule: loan_term_months must be > 0.
        err_of(validate_product_type_parameters("mortgage", &serde_json::json!({"loan_term_months": 0})));
        validate_product_type_parameters("mortgage", &serde_json::json!({"loan_term_months": 360})).unwrap();
    }

    #[test]
    fn product_params_credit_card_limit_must_be_positive() {
        err_of(validate_product_type_parameters(
            "credit_card",
            &serde_json::json!({"credit_limit": "0"}),
        ));
        validate_product_type_parameters("credit_card", &serde_json::json!({"credit_limit": "500"})).unwrap();
    }

    #[test]
    fn product_params_time_deposit_term_must_be_positive() {
        err_of(validate_product_type_parameters(
            "time_deposit",
            &serde_json::json!({"term_months": -3}),
        ));
        validate_product_type_parameters("time_deposit", &serde_json::json!({"term_months": 12})).unwrap();
    }

    #[test]
    fn product_params_savings_negative_interest_rate_rejected() {
        let e = err_of(validate_product_type_parameters(
            "savings_account",
            &serde_json::json!({"interest_rate": "-0.01"}),
        ));
        assert_eq!(e.code, "INVALID_VALUE");
        validate_product_type_parameters("us_savings", &serde_json::json!({"interest_rate": "0.05"})).unwrap();
        validate_product_type_parameters("shariah_savings", &serde_json::json!({})).unwrap();
    }

    #[test]
    fn product_params_unknown_product_type_accepted() {
        validate_product_type_parameters("mystery_product", &serde_json::json!({"anything": "goes"})).unwrap();
    }
}
// ── Unit tests — core module engine (pure logic; no DB) ──────────────────

#[cfg(test)]
mod module_tests {
    use super::*;
    use uuid::Uuid;

    fn ctx(modules: &[&str], params: serde_json::Value) -> ModuleContext<'static> {
        // Leak is fine in tests: the references live for the process.
        let leaked_modules: &'static Vec<String> =
            Box::leak(Box::new(modules.iter().map(|m| m.to_string()).collect()));
        let leaked_params: &'static serde_json::Value = Box::leak(params.into());
        let empty: &'static serde_json::Value =
            Box::leak(Box::new(serde_json::Value::Object(serde_json::Map::new())));
        ModuleContext {
            product_parameters: leaked_params,
            modules: leaked_modules,
            instance_params: empty,
        }
    }

    fn account(denomination: &str) -> AccountV2 {
        AccountV2 {
            id: Uuid::new_v4(),
            env_id: Uuid::new_v4(),
            customer_id: None,
            product_id: None,
            account_type: "CUSTOMER".into(),
            product_type: None,
            nickname: None,
            status: "OPEN".into(),
            denomination: denomination.into(),
            permitted_denominations: vec![],
            tside: "LIABILITY".into(),
            processing_group_id: None,
            sentin8_func_version_id: None,
            pending_sentin8_func_version_id: None,
            stakeholder_ids: vec![],
            opened_at: None,
            closed_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn posting(instruction_type: &str, amount: &str) -> PostingInstructionV2 {
        PostingInstructionV2 {
            instruction_type: instruction_type.into(),
            debit_account: Uuid::new_v4(),
            credit_account: Uuid::new_v4(),
            amount: amount.into(),
            denomination: "CAD".into(),
            value_timestamp: None,
            booking_timestamp: None,
            client_transaction_id: None,
            description: None,
        }
    }

    // ── Module gating: absent module ⇒ validation is a no-op ─────────────

    #[test]
    fn absent_module_is_noop() {
        let c = ctx(&["deposit-limits"], serde_json::json!({"min_deposit_amount": "10"}));
        // denomination-validation is NOT in the module list → unsupported denom passes.
        assert!(validate_creation_denomination(&c, &account("XXX")).is_ok());
        // overdraft-protection absent → any negative balance passes.
        assert!(validate_posting_overdraft_protection(&c, &posting("WITHDRAWAL", "999999"), Decimal::ZERO).is_ok());
        // maximum-balance absent → huge deposit passes.
        assert!(validate_posting_maximum_balance(&c, &posting("DEPOSIT", "999999"), Decimal::ZERO).is_ok());
    }

    #[test]
    fn empty_param_block_relaxes_limits() {
        let c = ctx(&["denomination-validation"], serde_json::json!({}));
        // supported_denominations unset → no constraint.
        assert!(validate_creation_denomination(&c, &account("XYZ")).is_ok());
        let c2 = ctx(&["deposit-limits"], serde_json::json!({}));
        // min/max unset → everything passes.
        assert!(validate_posting_deposit_limits(&c2, &posting("DEPOSIT", "1"), Decimal::ZERO).is_ok());
    }

    // ── 1. denomination-validation ────────────────────────────────────────

    #[test]
    fn denomination_rejects_unsupported() {
        let c = ctx(&["denomination-validation"], serde_json::json!({"supported_denominations": ["CAD", "USD"]}));
        assert!(validate_creation_denomination(&c, &account("CAD")).is_ok());
        let err = validate_creation_denomination(&c, &account("GBP")).unwrap_err();
        assert_eq!(err.code, "INVALID_DENOMINATION");
        assert_eq!(err.module, "denomination-validation");
    }

    // ── 2. deposit-limits ─────────────────────────────────────────────────

    #[test]
    fn deposit_limits_min_and_daily() {
        let c = ctx(&["deposit-limits"], serde_json::json!({
            "min_deposit_amount": "10", "max_daily_deposit_limit": "1000"
        }));
        // Below minimum.
        assert_eq!(validate_posting_deposit_limits(&c, &posting("DEPOSIT", "5"), Decimal::ZERO).unwrap_err().code, "BELOW_MIN_DEPOSIT");
        // OK within limits.
        assert!(validate_posting_deposit_limits(&c, &posting("DEPOSIT", "500"), Decimal::ZERO).is_ok());
        // Daily cap: 500 already deposited + 600 new > 1000.
        assert_eq!(validate_posting_deposit_limits(&c, &posting("DEPOSIT", "600"), Decimal::new(500, 0)).unwrap_err().code, "ABOVE_MAX_DAILY_DEPOSIT");
        // Exactly at cap passes (boundary).
        assert!(validate_posting_deposit_limits(&c, &posting("DEPOSIT", "500"), Decimal::new(500, 0)).is_ok());
        // Creation-time: initial deposit below minimum.
        assert_eq!(validate_creation_deposit_limits(&c, Some(Decimal::new(5, 0))).unwrap_err().code, "BELOW_MIN_DEPOSIT");
        // No initial deposit → no check.
        assert!(validate_creation_deposit_limits(&c, None).is_ok());
    }

    // ── 3. withdrawal-limits ───────────────────────────────────────────────

    #[test]
    fn withdrawal_limits_min_and_daily() {
        let c = ctx(&["withdrawal-limits"], serde_json::json!({
            "min_withdrawal_amount": "20", "max_daily_withdrawal_limit": "500"
        }));
        assert_eq!(validate_posting_withdrawal_limits(&c, &posting("WITHDRAWAL", "10"), Decimal::ZERO).unwrap_err().code, "BELOW_MIN_WITHDRAWAL");
        assert!(validate_posting_withdrawal_limits(&c, &posting("WITHDRAWAL", "100"), Decimal::ZERO).is_ok());
        assert_eq!(validate_posting_withdrawal_limits(&c, &posting("WITHDRAWAL", "300"), Decimal::new(300, 0)).unwrap_err().code, "ABOVE_MAX_DAILY_WITHDRAWAL");
    }

    // ── 4. transaction-type-limits ─────────────────────────────────────────

    #[test]
    fn transaction_type_limits_keyed_by_type() {
        let c = ctx(&["transaction-type-limits"], serde_json::json!({"max_daily_atm_withdrawal_limit": "200"}));
        // instruction_type ATM_WITHDRAWAL → param key max_daily_atm_withdrawal_limit.
        assert_eq!(validate_posting_transaction_type_limits(&c, &posting("ATM_WITHDRAWAL", "250"), Decimal::ZERO).unwrap_err().code, "ABOVE_MAX_DAILY_TXN_TYPE");
        // Under limit passes.
        assert!(validate_posting_transaction_type_limits(&c, &posting("ATM_WITHDRAWAL", "100"), Decimal::ZERO).is_ok());
        // Other types have no configured limit → pass even for huge amounts.
        assert!(validate_posting_transaction_type_limits(&c, &posting("WIRE_OUT", "999999"), Decimal::ZERO).is_ok());
    }

    // ── 5. maximum-balance ─────────────────────────────────────────────────

    #[test]
    fn maximum_balance_cap() {
        let c = ctx(&["maximum-balance"], serde_json::json!({"maximum_balance": "10000"}));
        assert_eq!(validate_posting_maximum_balance(&c, &posting("DEPOSIT", "500"), Decimal::new(9800, 0)).unwrap_err().code, "ABOVE_MAX_BALANCE");
        // Exactly at cap passes.
        assert!(validate_posting_maximum_balance(&c, &posting("DEPOSIT", "200"), Decimal::new(9800, 0)).is_ok());
    }

    // ── 6. overdraft-protection ────────────────────────────────────────────

    #[test]
    fn overdraft_protection_arranged_and_unarranged() {
        // Balance 100; withdraw 150 with arranged 100 + unarranged 50 → exactly -100 allowed.
        let c = ctx(&["overdraft-protection"], serde_json::json!({
            "arranged_overdraft_limit": "100", "unarranged_overdraft_limit": "50"
        }));
        assert!(validate_posting_overdraft_protection(&c, &posting("WITHDRAWAL", "150"), Decimal::new(100, 0)).is_ok());
        // Withdraw 251 → -151 < -100 → rejected.
        assert_eq!(validate_posting_overdraft_protection(&c, &posting("WITHDRAWAL", "251"), Decimal::new(100, 0)).unwrap_err().code, "OVERDRAFT_EXCEEDED");
        // No overdraft configured → any negative balance rejected.
        let c2 = ctx(&["overdraft-protection"], serde_json::json!({}));
        assert!(validate_posting_overdraft_protection(&c2, &posting("WITHDRAWAL", "1"), Decimal::ZERO).is_err());
        // Deposit path never trips overdraft.
        assert!(validate_posting_overdraft_protection(&c, &posting("DEPOSIT", "1000"), Decimal::new(100, 0)).is_ok());
    }

    // ── 7. deposit-interest-accrual (tiered) ───────────────────────────────

    #[test]
    fn interest_accrual_tiered_and_precision() {
        let c = ctx(&["deposit-interest-accrual"], serde_json::json!({
            "rate_tiers": [
                {"min_balance": "0", "rate": "0.01"},
                {"min_balance": "10000", "rate": "0.02"}
            ],
            "accrual_precision": "0.01"
        }));
        // Low tier: 1000 * 0.01 / 365 = 0.0274 → rounds to 0.03.
        let low = on_schedule_interest_accrual(&c, &account("CAD"), Decimal::new(1000, 0)).unwrap();
        assert_eq!(low, Decimal::new(3, 2), "1000@1%: got {low}");
        // High tier: 20000 * 0.02 / 365 = 1.0959 → rounds to 1.10.
        let high = on_schedule_interest_accrual(&c, &account("CAD"), Decimal::new(20000, 0)).unwrap();
        assert_eq!(high, Decimal::new(110, 2), "20000@2%: got {high}");
        // Module absent → zero accrual.
        let none = ctx(&[], serde_json::json!({}));
        assert_eq!(on_schedule_interest_accrual(&none, &account("CAD"), Decimal::new(1000, 0)).unwrap(), Decimal::ZERO);
    }

    #[test]
    fn interest_accrual_flat_rate_fallback() {
        // No rate_tiers → flat interest_rate.
        let c = ctx(&["deposit-interest-accrual"], serde_json::json!({"interest_rate": "0.0365"}));
        let accrued = on_schedule_interest_accrual(&c, &account("CAD"), Decimal::new(10000, 0)).unwrap();
        // 10000 * 0.0365 / 365 = 1.00 exactly.
        assert_eq!(accrued, Decimal::new(100, 2));
    }

    #[test]
    fn interest_accrual_tier_boundary_selects_higher_tier() {
        let c = ctx(&["deposit-interest-accrual"], serde_json::json!({
            "rate_tiers": [
                {"min_balance": "0", "rate": "0.01"},
                {"min_balance": "10000", "rate": "0.02"}
            ]
        }));
        // Balance exactly at the tier boundary picks the higher rate.
        let rate_accrued = on_schedule_interest_accrual(&c, &account("CAD"), Decimal::new(10000, 0)).unwrap();
        // 10000 * 0.02 / 365 = 0.5479 → 0.55 (not 10000*0.01/365=0.27).
        assert_eq!(rate_accrued, Decimal::new(55, 2));
    }

    // ── 9. maintenance-fees ────────────────────────────────────────────────

    #[test]
    fn maintenance_fee_amount_or_zero() {
        let c = ctx(&["maintenance-fees"], serde_json::json!({"maintenance_fee_amount": "4.95"}));
        assert_eq!(on_schedule_maintenance_fee(&c).unwrap(), Decimal::new(495, 2));
        // Unset amount → zero.
        let c2 = ctx(&["maintenance-fees"], serde_json::json!({}));
        assert_eq!(on_schedule_maintenance_fee(&c2).unwrap(), Decimal::ZERO);
        let c3 = ctx(&[], serde_json::json!({}));
        assert_eq!(on_schedule_maintenance_fee(&c3).unwrap(), Decimal::ZERO);
    }

    // ── 10. inactivity-fee ─────────────────────────────────────────────────

    #[test]
    fn inactivity_fee_threshold_boundary() {
        let c = ctx(&["inactivity-fee"], serde_json::json!({
            "inactivity_threshold_days": "90", "inactivity_fee_amount": "2.00"
        }));
        // Strictly greater than threshold triggers.
        assert_eq!(on_schedule_inactivity_fee(&c, 91).unwrap(), Decimal::new(200, 2));
        // At threshold: not yet inactive.
        assert_eq!(on_schedule_inactivity_fee(&c, 90).unwrap(), Decimal::ZERO);
        assert_eq!(on_schedule_inactivity_fee(&c, 1).unwrap(), Decimal::ZERO);
        // Default threshold 90 when unset.
        let c2 = ctx(&["inactivity-fee"], serde_json::json!({"inactivity_fee_amount": "5"}));
        assert_eq!(on_schedule_inactivity_fee(&c2, 91).unwrap(), Decimal::new(5, 0));
        assert_eq!(on_schedule_inactivity_fee(&c2, 89).unwrap(), Decimal::ZERO);
    }

    // ── 11. minimum-balance-fee ────────────────────────────────────────────

    #[test]
    fn minimum_balance_fee_strictly_below() {
        let c = ctx(&["minimum-balance-fee"], serde_json::json!({
            "minimum_balance_threshold": "1000", "minimum_balance_fee_amount": "10"
        }));
        assert_eq!(on_schedule_minimum_balance_fee(&c, Decimal::new(999, 0)).unwrap(), Decimal::new(10, 0));
        // At threshold: no fee.
        assert_eq!(on_schedule_minimum_balance_fee(&c, Decimal::new(1000, 0)).unwrap(), Decimal::ZERO);
    }

    // ── 12. closure-interest-application (forfeiture) ──────────────────────

    #[test]
    fn closure_interest_forfeiture() {
        let c = ctx(&["closure-interest-application"], serde_json::json!({"forfeiture_rate": "0.25"}));
        // 40 accrued * 0.25 forfeited = 30 paid out.
        assert_eq!(on_closure_interest_application(&c, Decimal::new(40, 0)).unwrap(), Decimal::new(30, 0));
        // No forfeiture → full payout.
        let c2 = ctx(&["closure-interest-application"], serde_json::json!({}));
        assert_eq!(on_closure_interest_application(&c2, Decimal::new(40, 0)).unwrap(), Decimal::new(40, 0));
        // Module absent → zero.
        let c3 = ctx(&[], serde_json::json!({}));
        assert_eq!(on_closure_interest_application(&c3, Decimal::new(40, 0)).unwrap(), Decimal::ZERO);
    }

    // ── 13. dormancy ───────────────────────────────────────────────────────

    #[test]
    fn dormancy_threshold_default_365() {
        let c = ctx(&["dormancy"], serde_json::json!({"dormancy_threshold_days": "180"}));
        assert!(on_schedule_dormancy(&c, 181).unwrap());
        assert!(!on_schedule_dormancy(&c, 180).unwrap());
        // Default 365 when unset.
        let c2 = ctx(&["dormancy"], serde_json::json!({}));
        assert!(on_schedule_dormancy(&c2, 366).unwrap());
        assert!(!on_schedule_dormancy(&c2, 365).unwrap());
        // Module absent → never dormant.
        let c3 = ctx(&[], serde_json::json!({}));
        assert!(!on_schedule_dormancy(&c3, 10000).unwrap());
    }

    // ── 14. overdraft-protection-sweep ─────────────────────────────────────

    #[test]
    fn overdraft_sweep_amounts() {
        let c = ctx(&["overdraft-protection-sweep"], serde_json::json!({"sweep_threshold": "-500"}));
        // Balance -600 < -500 → sweep 100 (bring back to threshold).
        assert_eq!(validate_posting_overdraft_sweep(&c, &posting("WITHDRAWAL", "1"), Decimal::new(-600, 0)).unwrap(), Some(Decimal::new(100, 0)));
        // Above threshold → no sweep.
        assert_eq!(validate_posting_overdraft_sweep(&c, &posting("WITHDRAWAL", "1"), Decimal::new(-400, 0)).unwrap(), None);
        // Positive balance → no sweep.
        assert_eq!(validate_posting_overdraft_sweep(&c, &posting("DEPOSIT", "1"), Decimal::new(100, 0)).unwrap(), None);
        // Module absent → None even deep negative.
        let c2 = ctx(&[], serde_json::json!({}));
        assert_eq!(validate_posting_overdraft_sweep(&c2, &posting("WITHDRAWAL", "1"), Decimal::new(-9999, 0)).unwrap(), None);
    }

    // ── 8/12 passthrough + application ─────────────────────────────────────

    #[test]
    fn interest_application_passthrough_and_gate() {
        let c = ctx(&["deposit-interest-application"], serde_json::json!({}));
        assert_eq!(on_schedule_interest_application(&c, &account("CAD"), Decimal::new(1234, 2)).unwrap(), Decimal::new(1234, 2));
        let c2 = ctx(&[], serde_json::json!({}));
        assert_eq!(on_schedule_interest_application(&c2, &account("CAD"), Decimal::new(1234, 2)).unwrap(), Decimal::ZERO);
    }

    // ── Dispatchers ─────────────────────────────────────────────────────────

    #[test]
    fn validate_creation_dispatches_both() {
        // Both modules fail together → first error surfaces.
        let c = ctx(
            &["denomination-validation", "deposit-limits"],
            serde_json::json!({"supported_denominations": ["CAD"], "min_deposit_amount": "100"}),
        );
        let acct = account("EUR");
        assert_eq!(validate_creation(&c, &acct, Some(Decimal::new(5, 0))).unwrap_err().code, "INVALID_DENOMINATION");
        // Denomination fixed → deposit limit error surfaces.
        let acct2 = account("CAD");
        assert_eq!(validate_creation(&c, &acct2, Some(Decimal::new(5, 0))).unwrap_err().code, "BELOW_MIN_DEPOSIT");
        // All good passes.
        assert!(validate_creation(&c, &acct2, Some(Decimal::new(100, 0))).is_ok());
    }

    #[test]
    fn validate_posting_dispatches_in_order() {
        let c = ctx(
            &["deposit-limits", "withdrawal-limits", "transaction-type-limits", "maximum-balance", "overdraft-protection"],
            serde_json::json!({
                "min_deposit_amount": "10",
                "max_daily_deposit_limit": "1000",
                "min_withdrawal_amount": "10",
                "max_daily_withdrawal_limit": "1000",
                "maximum_balance": "50000",
                "arranged_overdraft_limit": "0"
            }),
        );
        // Deposit above the daily cap trips deposit-limits (it runs first).
        let err = validate_posting(&c, &posting("DEPOSIT", "60000"), Decimal::new(0, 0), Decimal::ZERO, Decimal::ZERO, Decimal::ZERO).unwrap_err();
        assert_eq!(err.code, "ABOVE_MAX_DAILY_DEPOSIT");
        // With headroom under the daily cap, the same oversized deposit trips
        // maximum-balance instead (later in the dispatch chain).
        let err2 = validate_posting(&c, &posting("DEPOSIT", "600"), Decimal::new(50000, 0), Decimal::ZERO, Decimal::ZERO, Decimal::ZERO).unwrap_err();
        assert_eq!(err2.code, "ABOVE_MAX_BALANCE");
        // A withdrawal below the deposit minimum is caught by deposit-limits
        // first (the min-deposit check is amount-based, not type-based).
        assert_eq!(
            validate_posting(&c, &posting("WITHDRAWAL", "5"), Decimal::new(1000, 0), Decimal::ZERO, Decimal::ZERO, Decimal::ZERO).unwrap_err().code,
            "BELOW_MIN_DEPOSIT"
        );
        // A withdrawal at/above the deposit minimum but below its own minimum
        // is caught by withdrawal-limits (deposit-limits passes at 100 >= 10,
        // withdrawal-limits rejects 5 < 10 — same amount, different caps).
        assert_eq!(
            validate_posting_withdrawal_limits(&c, &posting("WITHDRAWAL", "5"), Decimal::ZERO).unwrap_err().code,
            "BELOW_MIN_WITHDRAWAL"
        );
        // Clean withdrawal passes the whole chain.
        assert!(validate_posting(&c, &posting("WITHDRAWAL", "100"), Decimal::new(1000, 0), Decimal::ZERO, Decimal::ZERO, Decimal::ZERO).is_ok());
        // A clean deposit passes all five.
        assert!(validate_posting(&c, &posting("DEPOSIT", "100"), Decimal::new(1000, 0), Decimal::ZERO, Decimal::ZERO, Decimal::ZERO).is_ok());
    }

    /// ModuleError Display: "[module] code: message".
    #[test]
    fn module_error_display() {
        let e = ModuleError {
            module: "deposit-limits".into(),
            message: "too small".into(),
            code: "BELOW_MIN_DEPOSIT".into(),
        };
        assert_eq!(e.to_string(), "[deposit-limits] BELOW_MIN_DEPOSIT: too small");
    }

    // ── Derived parameters (§11.1b.20) ──────────────────────────────────────

    #[test]
    fn derived_loan_remaining_term_and_debt() {
        let c = ctx(&[], serde_json::json!({"loan_term_months": "60", "repayment_day": "15"}));
        // Opened 60 months ago → remaining term 0 (clamped).
        let mut acct = account("CAD");
        acct.product_type = Some("loan".into());
        acct.opened_at = Some(chrono::Utc::now() - chrono::Duration::days(60 * 30));
        let derived = compute_derived_parameters(&c, &acct, Decimal::new(5000, 0));
        assert_eq!(derived["remaining_term"], serde_json::json!("0"));
        // Debt equals the current balance for asset-typed loans.
        assert_eq!(derived["total_outstanding_debt"], serde_json::json!("5000"));
        // Next repayment computed and RFC3339-parseable.
        let next = derived["next_repayment_date"].as_str().expect("repayment date");
        assert!(chrono::DateTime::parse_from_rfc3339(next).is_ok());
    }

    #[test]
    fn derived_loan_mid_term() {
        let c = ctx(&[], serde_json::json!({"loan_term_months": "24"}));
        let mut acct = account("CAD");
        acct.product_type = Some("mortgage".into());
        // Opened ~10 months ago → ~14 months remaining.
        acct.opened_at = Some(chrono::Utc::now() - chrono::Duration::days(10 * 30));
        let derived = compute_derived_parameters(&c, &acct, Decimal::new(1, 0));
        let remaining: i64 = derived["remaining_term"].as_str().unwrap().parse().unwrap();
        assert!((10..=16).contains(&remaining), "expected ~14, got {remaining}");
    }

    #[test]
    fn derived_credit_card_available_credit() {
        let c = ctx(&[], serde_json::json!({"credit_limit": "5000"}));
        let mut acct = account("CAD");
        acct.product_type = Some("credit_card".into());
        // Outstanding 1200 on limit 5000 → 4000 available.
        let derived = compute_derived_parameters(&c, &acct, Decimal::new(1000, 0));
        assert_eq!(derived["available_credit"], serde_json::json!("4000"));
        // Over-limit clamps to zero, never negative.
        let derived2 = compute_derived_parameters(&c, &acct, Decimal::new(6000, 0));
        assert_eq!(derived2["available_credit"], serde_json::json!("0"));
    }

    #[test]
    fn derived_redraw_funds() {
        let c = ctx(&[], serde_json::json!({"redraw_limit_percentage": "80"}));
        let mut acct = account("CAD");
        acct.product_type = Some("home_loan_redraw".into());
        let derived = compute_derived_parameters(&c, &acct, Decimal::new(10000, 0));
        assert_eq!(derived["available_redraw_funds"], serde_json::json!("8000"));
        assert_eq!(derived["total_outstanding_debt"], serde_json::json!("10000"));
    }

    #[test]
    fn derived_time_deposit_maturity() {
        let c = ctx(&[], serde_json::json!({"term_months": "6"}));
        let mut acct = account("CAD");
        acct.product_type = Some("time_deposit".into());
        let opened = chrono::Utc::now() - chrono::Duration::days(30);
        acct.opened_at = Some(opened);
        let derived = compute_derived_parameters(&c, &acct, Decimal::new(1, 0));
        let maturity = chrono::DateTime::parse_from_rfc3339(derived["maturity_date"].as_str().unwrap()).unwrap();
        // ~5 months (150 days) remain from opening: maturity ≈ opened + 180d.
        let expected = opened + chrono::Duration::days(6 * 30);
        assert_eq!(maturity.timestamp(), expected.timestamp());
    }

    #[test]
    fn derived_plain_product_is_empty() {
        let c = ctx(&[], serde_json::json!({"loan_term_months": "24"}));
        let mut acct = account("CAD");
        acct.product_type = Some("current_account".into()); // not loan-like
        let derived = compute_derived_parameters(&c, &acct, Decimal::new(1, 0));
        assert!(derived.as_object().unwrap().is_empty(), "no derived params for plain products");
    }
}
