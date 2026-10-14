// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Ledger domain types — full type definitions for all Ledger resources.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Account (v2) ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountV2 {
    pub id: Uuid,
    pub env_id: Uuid,
    pub customer_id: Option<Uuid>,
    pub product_id: Option<Uuid>,
    #[serde(rename = "type")]
    pub account_type: String, // CUSTOMER | INTERNAL
    pub product_type: Option<String>,
    pub nickname: Option<String>,
    pub status: String, // PENDING | OPEN | CLOSED | CANCELLED | CLOSING | OPENING
    pub denomination: String,
    pub permitted_denominations: Vec<String>,
    pub tside: String, // UNKNOWN | ASSET | LIABILITY
    pub processing_group_id: Option<String>,
    pub sentin8_func_version_id: Option<String>,
    pub pending_sentin8_func_version_id: Option<String>,
    pub stakeholder_ids: Vec<Uuid>,
    pub opened_at: Option<chrono::DateTime<chrono::Utc>>,
    pub closed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateAccountV2Request {
    pub product_id: Option<Uuid>,
    pub customer_id: Option<Uuid>,
    #[serde(rename = "type")]
    pub account_type: String,
    pub product_type: Option<String>,
    pub nickname: Option<String>,
    #[serde(default = "default_denom")]
    pub denomination: String,
    #[serde(default)]
    pub permitted_denominations: Vec<String>,
    #[serde(default)]
    pub tside: String,
    #[serde(default)]
    pub processing_group_id: Option<String>,
    #[serde(default)]
    pub sentin8_func_version_id: Option<String>,
    #[serde(default)]
    pub stakeholder_ids: Vec<Uuid>,
    #[serde(default)]
    pub instance_param_vals: serde_json::Value,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
    #[serde(default)]
    pub status: Option<String>,
}

fn default_denom() -> String { "CAD".into() }

#[derive(Debug, Deserialize)]
pub struct UpdateAccountV2Request {
    pub status: Option<String>,
    pub nickname: Option<String>,
    pub sentin8_func_version_id: Option<String>,
    pub instance_param_vals: Option<serde_json::Value>,
}

// ── Balance (v2) ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct BalanceV2 {
    pub account_id: Uuid,
    pub denomination: String,
    pub address: String,
    pub phase: String, // COMMITTED | PENDING_IN | PENDING_OUT
    pub amount: String,
    pub asset: String,
    pub value_timestamp: chrono::DateTime<chrono::Utc>,
}

// ── Posting ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostingInstructionV2 {
    pub instruction_type: String, // 9 types
    pub debit_account: Uuid,
    pub credit_account: Uuid,
    pub amount: String,
    #[serde(default = "default_denom")]
    pub denomination: String,
    #[serde(default)]
    pub value_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub booking_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub client_transaction_id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePostingBatchRequest {
    pub batch_id: String,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_transaction_id: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub shard_key: Option<String>,
    pub instructions: Vec<PostingInstructionV2>,
}

#[derive(Debug, Serialize)]
pub struct PostingBatchResponse {
    pub id: Uuid,
    pub batch_id: String,
    pub status: String,
    pub instruction_count: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub balances: Vec<BalanceV2>,
}

// ── Schedule ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ScheduleResponse {
    pub id: Uuid,
    pub account_id: Option<Uuid>,
    pub schedule_type: String,
    pub cron_expression: String,
    pub status: String,
    pub last_run_at: Option<chrono::DateTime<chrono::Utc>>,
    pub next_run_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateScheduleRequest {
    pub account_id: Option<Uuid>,
    pub schedule_type: String,
    pub cron_expression: String,
}

// ── Job ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct JobResponse {
    pub id: Uuid,
    pub schedule_id: Option<Uuid>,
    pub job_type: String,
    pub status: String,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ── Flag ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct FlagDefinitionResponse {
    pub id: Uuid,
    pub flag_name: String,
    pub required_flag_level: String,
    pub flag_visibility: String,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateFlagDefinitionRequest {
    pub flag_name: String,
    pub required_flag_level: Option<String>,
    pub flag_visibility: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlagResponse {
    pub id: Uuid,
    pub flag_definition_id: Uuid,
    pub account_id: Option<Uuid>,
    pub customer_id: Option<Uuid>,
    pub value: String,
    pub effective_timestamp: chrono::DateTime<chrono::Utc>,
    pub expiry_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateFlagRequest {
    pub flag_definition_id: Uuid,
    pub account_id: Option<Uuid>,
    pub customer_id: Option<Uuid>,
    #[serde(default = "default_on")]
    pub value: String,
    pub effective_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub expiry_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

fn default_on() -> String { "ON".into() }

// ── Restriction ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct RestrictionDefinitionResponse {
    pub id: Uuid,
    pub action: String,
    pub description: Option<String>,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRestrictionDefinitionRequest {
    pub action: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestrictionSetResponse {
    pub id: Uuid,
    pub restriction_definition_id: Uuid,
    pub account_id: Option<Uuid>,
    pub customer_id: Option<Uuid>,
    pub status: String,
    pub effective_timestamp: chrono::DateTime<chrono::Utc>,
    pub expiry_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRestrictionSetRequest {
    pub restriction_definition_id: Uuid,
    pub account_id: Option<Uuid>,
    pub customer_id: Option<Uuid>,
    pub expiry_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

// ── Parameter ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ParameterResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub is_instance: bool,
    pub is_template: bool,
    pub is_derived: bool,
    pub data_type: String,
    pub constraints: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateParameterRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub is_instance: bool,
    #[serde(default = "default_true")]
    pub is_template: bool,
    #[serde(default)]
    pub is_derived: bool,
    #[serde(default = "default_string")]
    pub data_type: String,
    #[serde(default)]
    pub constraints: serde_json::Value,
}

fn default_true() -> bool { true }
fn default_string() -> String { "string".into() }

#[derive(Debug, Clone, Serialize)]
pub struct ParameterValueResponse {
    pub id: Uuid,
    pub parameter_id: Uuid,
    pub account_id: Option<Uuid>,
    pub hierarchy_node_id: Option<Uuid>,
    pub is_global: bool,
    pub value: serde_json::Value,
    pub effective_from_timestamp: chrono::DateTime<chrono::Utc>,
    pub effective_to_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateParameterValueRequest {
    pub parameter_id: Uuid,
    pub account_id: Option<Uuid>,
    pub hierarchy_node_id: Option<Uuid>,
    #[serde(default)]
    pub is_global: bool,
    pub value: serde_json::Value,
    #[serde(default)]
    pub effective_from_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

// ── Customer ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct CustomerResponse {
    pub id: Uuid,
    pub display_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCustomerRequest {
    pub display_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
}

// ── Transaction ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct TransactionResponse {
    pub id: Uuid,
    pub account_id: Uuid,
    pub posting_id: Uuid,
    pub amount: String,
    pub denomination: String,
    pub direction: String,
    pub description: Option<String>,
    pub value_timestamp: chrono::DateTime<chrono::Utc>,
    pub booking_timestamp: chrono::DateTime<chrono::Utc>,
}

// ── Statement ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct StatementResponse {
    pub id: Uuid,
    pub account_id: Uuid,
    pub period_start: chrono::DateTime<chrono::Utc>,
    pub period_end: chrono::DateTime<chrono::Utc>,
    pub opening_balance: String,
    pub closing_balance: String,
    pub document_url: Option<String>,
    pub document_format: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ── DLQ ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct DlqResponse {
    pub id: Uuid,
    pub message_type: String,
    pub payload: serde_json::Value,
    pub error_message: String,
    pub retry_count: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ── Audit ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct AuditEventResponse {
    pub id: Uuid,
    pub actor_user_id: Option<String>,
    pub action: String,
    pub target_resource_type: Option<String>,
    pub target_resource_id: Option<String>,
    pub correlation_id: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

// ── Product Version ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ProductVersionResponse {
    pub id: Uuid,
    pub product_id: Uuid,
    pub version_number: i32,
    pub tside: String,
    pub contract_modules: serde_json::Value,
    pub supported_denominations: Vec<String>,
    pub parameters: serde_json::Value,
    pub expected_parameters: serde_json::Value,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateProductVersionRequest {
    pub product_id: Uuid,
    pub tside: Option<String>,
    #[serde(default)]
    pub contract_modules: serde_json::Value,
    #[serde(default)]
    pub supported_denominations: Vec<String>,
    #[serde(default)]
    pub parameters: serde_json::Value,
    #[serde(default)]
    pub expected_parameters: serde_json::Value,
}

// ── Calendar ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct CalendarResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub timezone: String,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCalendarRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "default_utc")]
    pub timezone: String,
}

fn default_utc() -> String { "UTC".into() }