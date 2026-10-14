// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

// Ledger integration tests — Story
use bank8_ledger_server::modules::{validate_module_composition, validate_product_type_parameters};

#[test]
fn test_validate_module_composition_current_account_overdraft_ok() {
    let modules = vec![
        "denomination-validation".to_string(),
        "overdraft-protection".to_string(),
    ];
    assert!(validate_module_composition("current_account", &modules).is_ok());
}

#[test]
fn test_validate_module_composition_savings_no_overdraft() {
    let modules = vec!["overdraft-protection".to_string()];
    assert!(validate_module_composition("savings_account", &modules).is_err());
}

#[test]
fn test_validate_module_composition_empty() {
    let modules: Vec<String> = vec![];
    assert!(validate_module_composition("current_account", &modules).is_ok());
}

#[test]
fn test_validate_module_composition_unknown_product() {
    let modules = vec!["denomination-validation".to_string()];
    assert!(validate_module_composition("unknown_product", &modules).is_ok());
}

#[test]
fn test_validate_product_type_parameters_valid() {
    let params = serde_json::json!({"minimum_deposit": "100", "maximum_daily_deposit": "5000"});
    assert!(validate_product_type_parameters("savings_account", &params).is_ok());
}

#[test]
fn test_validate_product_type_parameters_mortgage_due_day_invalid() {
    let params = serde_json::json!({"due_amount_calculation_day": 35});
    assert!(validate_product_type_parameters("mortgage", &params).is_err());
}

#[test]
fn test_validate_product_type_parameters_mortgage_due_day_valid() {
    let params = serde_json::json!({"due_amount_calculation_day": "15"});
    assert!(validate_product_type_parameters("mortgage", &params).is_ok());
}

#[test]
fn test_validate_product_type_parameters_empty_params() {
    let params = serde_json::json!({});
    assert!(validate_product_type_parameters("current_account", &params).is_ok());
}

#[test]
fn test_validate_product_type_parameters_unknown_product() {
    let params = serde_json::json!({});
    assert!(validate_product_type_parameters("unknown_product", &params).is_ok());
}
