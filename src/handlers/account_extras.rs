// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Account extras - account attributes and payment devices.
//! - Attributes: free-form keyed values per account
//! (`account_attributes`).
//! - Payment devices: card/token devices attached to an account
//! (`payment_devices`). `device_token_ref` is a **secret reference**
//! - never raw PAN/token material (§4.4).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{emit_event, err_db, set_tenant_context_ext, AppState};

// ── Account attributes  ───────────────────────────────────────────

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct AccountAttributeResponse {
    pub account_id: Uuid,
    pub attribute_key: String,
    pub value: JsonValue,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertAccountAttributeRequest {
    pub attribute_key: String,
    pub value: JsonValue,
}

/// `GET /v1/accounts/{id}/attributes` - list account attribute values.
#[utoipa::path(
    get,
    path = "/v1/accounts/{id}/attributes",
    responses(
        (status = 200, description = "Account attributes", body = [AccountAttributeResponse]),
        (status = 403, description = "Missing bank8:ledger:accounts:read scope"),
    ),
    security(("bank8:ledger:accounts:read" = [])),
    tag = "ledger",
)]
pub async fn list_account_attributes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<AccountAttributeResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, a.env_id(), &a)
        .await
        .map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT account_id, attribute_key, value, updated_at
             FROM account_attributes WHERE env_id = $1 AND account_id = $2
            ORDER BY attribute_key"#,
    )
    .bind(a.env_id())
    .bind(id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| AccountAttributeResponse {
                account_id: r.get("account_id"),
                attribute_key: r.get("attribute_key"),
                value: r.get("value"),
                updated_at: r.get("updated_at"),
            })
            .collect(),
    ))
}

/// `PUT /v1/accounts/{id}/attributes` - upsert account attribute values.
#[utoipa::path(
    put,
    path = "/v1/accounts/{id}/attributes",
    request_body = UpsertAccountAttributeRequest,
    responses(
        (status = 200, description = "Attribute upserted", body = AccountAttributeResponse),
        (status = 403, description = "Missing bank8:ledger:accounts:write scope"),
    ),
    security(("bank8:ledger:accounts:write" = [])),
    tag = "ledger",
)]
pub async fn upsert_account_attribute(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertAccountAttributeRequest>,
) -> Result<Json<AccountAttributeResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:write"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, a.env_id(), &a)
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"INSERT INTO account_attributes (env_id, account_id, attribute_key, value)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (account_id, attribute_key) DO UPDATE
             SET value = EXCLUDED.value, updated_at = now()
           RETURNING account_id, attribute_key, value, updated_at"#,
    )
    .bind(a.env_id())
    .bind(id)
    .bind(&req.attribute_key)
    .bind(&req.value)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:account:updated",
        serde_json::json!({ "account_id": id, "fields_changed": ["attributes"] }),
    )
    .await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(AccountAttributeResponse {
        account_id: row.get("account_id"),
        attribute_key: row.get("attribute_key"),
        value: row.get("value"),
        updated_at: row.get("updated_at"),
    }))
}

// ── Payment devices  ──────────────────────────────────────────────

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct PaymentDeviceResponse {
    pub id: Uuid,
    pub account_id: Uuid,
    pub device_type: String,
    pub device_token_ref: String,
    pub status: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AttachPaymentDeviceRequest {
    pub device_type: String,
    /// Secret reference (never raw PAN/token material) - §4.4 secret references.
    pub device_token_ref: String,
}

/// `POST /v1/accounts/{id}/devices` - attach a payment device.
#[utoipa::path(
    post,
    path = "/v1/accounts/{id}/devices",
    request_body = AttachPaymentDeviceRequest,
    responses(
        (status = 200, description = "Device attached", body = PaymentDeviceResponse),
        (status = 403, description = "Missing bank8:ledger:accounts:write scope"),
    ),
    security(("bank8:ledger:accounts:write" = [])),
    tag = "ledger",
)]
pub async fn attach_payment_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<AttachPaymentDeviceRequest>,
) -> Result<Json<PaymentDeviceResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:write"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, a.env_id(), &a)
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"INSERT INTO payment_devices (env_id, account_id, device_type, device_token_ref)
           VALUES ($1, $2, $3, $4)
           RETURNING id, account_id, device_type, device_token_ref, status"#,
    )
    .bind(a.env_id())
    .bind(id)
    .bind(&req.device_type)
    .bind(&req.device_token_ref)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let device_id: Uuid = row.get("id");
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:paymentdevice:created",
        serde_json::json!({ "device_id": device_id, "account_id": id }),
    )
    .await;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(PaymentDeviceResponse {
        id: device_id,
        account_id: row.get("account_id"),
        device_type: row.get("device_type"),
        device_token_ref: row.get("device_token_ref"),
        status: row.get("status"),
    }))
}

/// `GET /v1/accounts/{id}/devices` - list attached payment devices.
#[utoipa::path(
    get,
    path = "/v1/accounts/{id}/devices",
    responses(
        (status = 200, description = "Payment devices", body = [PaymentDeviceResponse]),
        (status = 403, description = "Missing bank8:ledger:accounts:read scope"),
    ),
    security(("bank8:ledger:accounts:read" = [])),
    tag = "ledger",
)]
pub async fn list_payment_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<PaymentDeviceResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, a.env_id(), &a)
        .await
        .map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT id, account_id, device_type, device_token_ref, status
             FROM payment_devices WHERE env_id = $1 AND account_id = $2
            ORDER BY created_at DESC"#,
    )
    .bind(a.env_id())
    .bind(id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| PaymentDeviceResponse {
                id: r.get("id"),
                account_id: r.get("account_id"),
                device_type: r.get("device_type"),
                device_token_ref: r.get("device_token_ref"),
                status: r.get("status"),
            })
            .collect(),
    ))
}
