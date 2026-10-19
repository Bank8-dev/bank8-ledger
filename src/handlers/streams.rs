// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Streaming catalog - the client-facing "Core Streaming API" view.
//! The ledger emits domain events on the shared `bus:{envId}:ledger` stream
//! family (Sentin8:Bus inbox-first, design §11). This endpoint surfaces the
//! `event_type` families a client can subscribe to; the external topic
//! `sentin8.ledger.${tenant_id}.stream_api.v1.{family}.{resource}.events`
//! maps onto the bus stream with `event_type` filters (tenant_id = env_id).

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::Value as JsonValue;

use crate::auth;
use crate::handlers::AppState;

/// `GET /v1/streams` - client-facing streaming catalog: the `event_type`
/// families the ledger emits on the `bus:{envId}:ledger` stream family
/// (business "Core Streaming API"; topic mapping in design §11).
#[utoipa::path(
    get,
    path = "/v1/streams",
    responses(
        (status = 200, description = "Emitted event families"),
        (status = 403, description = "Missing bank8:ledger:accounts:read scope"),
    ),
    security(("bank8:ledger:accounts:read" = [])),
    tag = "ledger",
)]
pub async fn list_streams(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:accounts:read"),
    )
    .await?;
    Ok(Json(serde_json::json!({
        "stream_family": "ledger",
        "note": "external topic sentin8.ledger.${tenant_id}.stream_api.v1.{family}.{resource}.events maps to bus:{envId}:ledger with event_type filters; tenant_id = env_id",
        "event_types": [
            "bank8:ledger:posting:created", "bank8:ledger:posting:async:request",
            "bank8:ledger:posting:republished", "bank8:ledger:account:created",
            "bank8:ledger:account:updated", "bank8:ledger:product:created",
            "bank8:ledger:product:updated", "bank8:ledger:product:activated",
            "bank8:ledger:productversion:created", "bank8:ledger:schedule:created",
            "bank8:ledger:calendar:created", "bank8:ledger:calendarevent:created",
            "bank8:ledger:bookkeepingdate:updated", "bank8:ledger:job:retried",
            "bank8:ledger:job:batchrepublished", "bank8:ledger:flagdefinition:created",
            "bank8:ledger:flag:created", "bank8:ledger:restrictiondefinition:created",
            "bank8:ledger:restrictionset:created", "bank8:ledger:parameter:created",
            "bank8:ledger:parametervalue:created", "bank8:ledger:hierarchynode:created",
            "bank8:ledger:customer:created", "bank8:ledger:customer:updated",
            "bank8:ledger:customer:authlinked", "bank8:ledger:adjustment:created",
            "bank8:ledger:plan:created", "bank8:ledger:planmigration:created",
            "bank8:ledger:processinggroup:updated", "bank8:ledger:scheduletag:created",
            "bank8:ledger:paymentdevice:created", "bank8:ledger:internalaccount:created",
            "bank8:ledger:supervisorcontract:created", "bank8:ledger:journal:replayed"
        ]
    })))
}
