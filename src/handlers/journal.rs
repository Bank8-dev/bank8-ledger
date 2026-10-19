// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Journal events - append-only, hash-chained audit journal.
//! The journal is written in the same DB transaction as the domain change
//! (postings, adjustments, plan migrations, contract simulations, bulk
//! batches - design §5.3). Every row chains to the previous row's checksum:
//! `checksum = SHA-256(prev_checksum, resource_type, resource_id, operation,
//! payload)` - tamper-evident by construction. `append_journal_event` is the
//! single write path; the posting engine (`handlers/postings.rs`) calls it
//! inside its commit transaction.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{emit_event, err_db, set_tenant_context, AppState};

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct JournalEventResponse {
    pub id: Uuid,
    pub resource_type: String,
    pub resource_id: Uuid,
    pub operation: String,
    pub payload: JsonValue,
    pub prev_checksum: Option<String>,
    pub checksum: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Journal checksum: SHA-256 over (prev_checksum, resource_type,
/// resource_id, operation, payload) - the tamper-evident chain link
/// (design §5.3). Pure function so the chain properties are unit-testable.
pub(crate) fn journal_checksum(
    prev: Option<&str>,
    resource_type: &str,
    resource_id: Uuid,
    operation: &str,
    payload: &JsonValue,
) -> String {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(prev.unwrap_or("").as_bytes());
    hasher.update(resource_type.as_bytes());
    hasher.update(resource_id.as_bytes().as_slice());
    hasher.update(operation.as_bytes());
    hasher.update(payload.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Append a journal event inside the caller's transaction. The checksum is a
/// SHA-256 over the row contents chained to the previous row's checksum
/// (tamper-evident append-only journal; design §5.3). Called by the posting
/// path and the domain write handlers across the handler modules.
pub async fn append_journal_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    env_id: Uuid,
    resource_type: &str,
    resource_id: Uuid,
    operation: &str,
    payload: &JsonValue,
) -> Result<(), (StatusCode, String)> {
    let prev: Option<String> = sqlx::query_scalar(
        "SELECT checksum FROM journal_events WHERE env_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(env_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(err_db)?;

    let checksum = journal_checksum(
        prev.as_deref(),
        resource_type,
        resource_id,
        operation,
        payload,
    );

    sqlx::query(
        r#"INSERT INTO journal_events (env_id, resource_type, resource_id, operation, payload, prev_checksum, checksum)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(env_id).bind(resource_type).bind(resource_id).bind(operation)
    .bind(payload).bind(prev.as_deref()).bind(&checksum)
    .execute(&mut **tx)
    .await
    .map_err(err_db)?;
    Ok(())
}

/// `GET /v1/journal-events` - query the journal.
#[utoipa::path(
    get,
    path = "/v1/journal-events",
    params(
        ("resource_type" = Option<String>, Query, description = "Filter by resource type"),
        ("resource_id" = Option<Uuid>, Query, description = "Filter by resource id"),
    ),
    responses(
        (status = 200, description = "Journal events (newest first)", body = [JournalEventResponse]),
        (status = 403, description = "Missing bank8:ledger:postings:read scope"),
    ),
    security(("bank8:ledger:postings:read" = [])),
    tag = "ledger",
)]
pub async fn list_journal_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListJournalQuery>,
) -> Result<Json<Vec<JournalEventResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT id, resource_type, resource_id, operation, payload, prev_checksum, checksum, created_at
             FROM journal_events
            WHERE ($1::text IS NULL OR resource_type = $1)
              AND ($2::uuid IS NULL OR resource_id = $2)
            ORDER BY created_at DESC, id DESC LIMIT 200"#,
    )
    .bind(q.resource_type.as_deref())
    .bind(q.resource_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| JournalEventResponse {
                id: r.get("id"),
                resource_type: r.get("resource_type"),
                resource_id: r.get("resource_id"),
                operation: r.get("operation"),
                payload: r.get("payload"),
                prev_checksum: r.get("prev_checksum"),
                checksum: r.get("checksum"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListJournalQuery {
    #[serde(default)]
    pub resource_type: Option<String>,
    #[serde(default)]
    pub resource_id: Option<Uuid>,
}

/// `GET /v1/journal-events/{id}` - one journal event.
#[utoipa::path(
    get,
    path = "/v1/journal-events/{id}",
    responses(
        (status = 200, description = "Journal event", body = JournalEventResponse),
        (status = 404, description = "Not found"),
    ),
    security(("bank8:ledger:postings:read" = [])),
    tag = "ledger",
)]
pub async fn get_journal_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JournalEventResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"SELECT id, resource_type, resource_id, operation, payload, prev_checksum, checksum, created_at
             FROM journal_events WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, format!("journal event {id} not found")))?;
    Ok(Json(JournalEventResponse {
        id: row.get("id"),
        resource_type: row.get("resource_type"),
        resource_id: row.get("resource_id"),
        operation: row.get("operation"),
        payload: row.get("payload"),
        prev_checksum: row.get("prev_checksum"),
        checksum: row.get("checksum"),
        created_at: row.get("created_at"),
    }))
}

/// `POST /v1/journal-events/{id}/replay` - re-drive a journal event
/// idempotently . The journal row carries the full operation payload;
/// posting replays are no-ops thanks to posting idempotency keys. Other
/// resource kinds re-apply the recorded operation.
#[utoipa::path(
    post,
    path = "/v1/journal-events/{id}/replay",
    responses(
        (status = 200, description = "Replay accepted (result object)"),
        (status = 404, description = "Journal event not found"),
    ),
    security(("bank8:ledger:postings:write" = [])),
    tag = "ledger",
)]
pub async fn replay_journal_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:postings:write"),
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"SELECT id, resource_type, resource_id, operation, payload
             FROM journal_events WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?
    .ok_or((
        StatusCode::NOT_FOUND,
        format!("journal event {id} not found"),
    ))?;

    let resource_type: String = row.get("resource_type");
    let resource_id: Uuid = row.get("resource_id");
    let operation: String = row.get("operation");
    let payload: JsonValue = row.get("payload");

    // Posting replay: re-drive the recorded instruction set through the
    // normal posting path. Posting idempotency (batch_id) makes replays
    // no-ops - the original batch row is returned untouched.
    let result = if resource_type == "posting" {
        let batch_id = payload
            .get("batch_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let instructions = payload
            .get("instructions")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));
        let replayed =
            crate::handlers::postings::replay_batch(&state, a.env_id(), &batch_id, instructions)
                .await;
        serde_json::json!({ "kind": "posting", "batch_id": batch_id, "result": replayed })
    } else {
        // Non-posting kinds: the domain write already happened; replay
        // re-emits the corresponding Bus event (idempotent consumers).
        emit_event(
            &state.pool,
            a.env_id(),
            &format!("bank8:ledger:journal:replayed:{resource_type}:{operation}"),
            serde_json::json!({ "journal_event_id": id, "resource_id": resource_id }),
        )
        .await;
        serde_json::json!({ "kind": resource_type, "resource_id": resource_id, "replayed": true })
    };

    // The replay itself is journaled (append-only audit of replays).
    append_journal_event(
        &mut tx,
        a.env_id(),
        "journal",
        id,
        "replay",
        &serde_json::json!({ "source_event": id, "operation": operation }),
    )
    .await?;
    emit_event(
        &state.pool,
        a.env_id(),
        "bank8:ledger:journal:replayed",
        serde_json::json!({ "journal_event_id": id, "result": result }),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    Ok(Json(result))
}

// ── Unit tests (§8.6 conventions - pure logic, no DB) ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Journal checksum: deterministic for identical input, distinct for a
    /// chained prev, 64-hex (SHA-256). Tests the REAL journal_checksum fn
    /// (the same one append_journal_event persists), not a local copy.
    #[test]
    fn journal_checksum_binds_prev() {
        let id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let payload = serde_json::json!({ "amount": "10.00" });
        let c1 = journal_checksum(None, "posting", id, "create", &payload);
        let c2 = journal_checksum(None, "posting", id, "create", &payload);
        let c3 = journal_checksum(Some(&c1), "posting", id, "create", &payload);
        // Same input → same checksum (deterministic).
        assert_eq!(c1, c2);
        // Chained: a different prev produces a different checksum.
        assert_ne!(c1, c3);
        assert_eq!(c1.len(), 64); // SHA-256 hex
    }

    /// Any single-field change must break the chain link (tamper evidence).
    #[test]
    fn journal_checksum_tamper_evidence() {
        let id = Uuid::new_v4();
        let p = serde_json::json!({ "amount": "10.00" });
        let base = journal_checksum(None, "posting", id, "create", &p);
        // Payload tampered.
        assert_ne!(
            base,
            journal_checksum(
                None,
                "posting",
                id,
                "create",
                &serde_json::json!({ "amount": "99.00" })
            )
        );
        // Operation tampered.
        assert_ne!(base, journal_checksum(None, "posting", id, "amend", &p));
        // Resource type tampered.
        assert_ne!(base, journal_checksum(None, "adjustment", id, "create", &p));
        // Resource id tampered.
        assert_ne!(
            base,
            journal_checksum(None, "posting", Uuid::new_v4(), "create", &p)
        );
    }

    /// Known-vector: the exact digest for a fixed input pins the algorithm
    /// (any accidental change to the byte layout fails this test).
    #[test]
    fn journal_checksum_known_vector() {
        let id = Uuid::nil();
        let c = journal_checksum(None, "posting", id, "create", &serde_json::json!({}));
        // sha256("" + "posting" + nil-uuid bytes + "create" + "{}")
        let mut h = sha2::Sha256::new();
        use sha2::Digest;
        h.update(b"");
        h.update(b"posting");
        h.update([0u8; 16]);
        h.update(b"create");
        h.update(r#"{}"#.as_bytes());
        assert_eq!(c, format!("{:x}", h.finalize()));
        // And the captain checksum differs from the same event chained on it.
        assert_ne!(
            c,
            journal_checksum(Some(&c), "posting", id, "create", &serde_json::json!({}))
        );
    }
}
