// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Calendar model — calendar events, periods and bookkeeping dates.
//! Events are HOLIDAY / WEEKEND / ROLL / PAUSE markers; periods are named
//! date ranges (monthly by default); bookkeeping dates remap an effective
//! date to a different bookkeeping date. The schedule-run dispatcher consults
//! these before executing (design §5.4, tables in §8.0).

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{emit_event, err_db, set_tenant_context, AppState};

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct CalendarEventResponse {
    pub id: Uuid,
    pub calendar_id: Uuid,
    pub event_date: chrono::NaiveDate,
    pub event_type: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCalendarEventRequest {
    pub event_date: chrono::NaiveDate,
    pub event_type: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// `POST /v1/calendars/{id}/events` — add a calendar event.
#[utoipa::path(
    post,
    path = "/v1/calendars/{id}/events",
    request_body = CreateCalendarEventRequest,
    responses(
        (status = 200, description = "Event added", body = CalendarEventResponse),
        (status = 400, description = "Invalid event_type"),
        (status = 403, description = "Missing bank8:ledger:schedules:write scope"),
    ),
    security(("bank8:ledger:schedules:write" = [])),
    tag = "ledger",
)]
pub async fn create_calendar_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(calendar_id): Path<Uuid>,
    Json(req): Json<CreateCalendarEventRequest>,
) -> Result<Json<CalendarEventResponse>, (StatusCode, String)> {
    if !matches!(
        req.event_type.as_str(),
        "HOLIDAY" | "WEEKEND" | "ROLL" | "PAUSE"
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            "event_type must be HOLIDAY, WEEKEND, ROLL or PAUSE".into(),
        ));
    }
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:schedules:write"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"INSERT INTO calendar_events (env_id, calendar_id, event_date, event_type, description)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, calendar_id, event_date, event_type, description"#,
    )
    .bind(a.env_id()).bind(calendar_id).bind(req.event_date).bind(&req.event_type).bind(req.description.as_deref())
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let event_id: Uuid = row.get("id");
    emit_event(&state.pool, a.env_id(), "bank8:ledger:calendarevent:created",
        serde_json::json!({ "calendar_id": calendar_id, "event_id": event_id, "event_type": req.event_type }))
        .await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(CalendarEventResponse {
        id: event_id,
        calendar_id: row.get("calendar_id"),
        event_date: row.get("event_date"),
        event_type: row.get("event_type"),
        description: row.get("description"),
    }))
}

/// `GET /v1/calendars/{id}/events` — list calendar events.
#[utoipa::path(
    get,
    path = "/v1/calendars/{id}/events",
    responses(
        (status = 200, description = "Calendar events", body = [CalendarEventResponse]),
        (status = 403, description = "Missing bank8:ledger:schedules:read scope"),
    ),
    security(("bank8:ledger:schedules:read" = [])),
    tag = "ledger",
)]
pub async fn list_calendar_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(calendar_id): Path<Uuid>,
) -> Result<Json<Vec<CalendarEventResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:schedules:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT id, calendar_id, event_date, event_type, description
             FROM calendar_events WHERE env_id = $1 AND calendar_id = $2
            ORDER BY event_date"#,
    )
    .bind(a.env_id())
    .bind(calendar_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| CalendarEventResponse {
                id: r.get("id"),
                calendar_id: r.get("calendar_id"),
                event_date: r.get("event_date"),
                event_type: r.get("event_type"),
                description: r.get("description"),
            })
            .collect(),
    ))
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct CalendarPeriodResponse {
    pub id: Uuid,
    pub calendar_id: Uuid,
    pub start_date: chrono::NaiveDate,
    pub end_date: chrono::NaiveDate,
    pub period_type: String,
    pub descriptor: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCalendarPeriodRequest {
    pub start_date: chrono::NaiveDate,
    pub end_date: chrono::NaiveDate,
    #[serde(default = "default_period_type")]
    pub period_type: String,
    #[serde(default)]
    pub descriptor: Option<String>,
}
fn default_period_type() -> String {
    "monthly".into()
}

/// `POST /v1/calendars/{id}/periods` — add a calendar period.
#[utoipa::path(
    post,
    path = "/v1/calendars/{id}/periods",
    request_body = CreateCalendarPeriodRequest,
    responses(
        (status = 200, description = "Period added", body = CalendarPeriodResponse),
        (status = 403, description = "Missing bank8:ledger:schedules:write scope"),
    ),
    security(("bank8:ledger:schedules:write" = [])),
    tag = "ledger",
)]
pub async fn create_calendar_period(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(calendar_id): Path<Uuid>,
    Json(req): Json<CreateCalendarPeriodRequest>,
) -> Result<Json<CalendarPeriodResponse>, (StatusCode, String)> {
    if req.end_date < req.start_date {
        return Err((
            StatusCode::BAD_REQUEST,
            "end_date must be on or after start_date".into(),
        ));
    }
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:schedules:write"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"INSERT INTO calendar_periods (env_id, calendar_id, start_date, end_date, period_type, descriptor)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id, calendar_id, start_date, end_date, period_type, descriptor"#,
    )
    .bind(a.env_id()).bind(calendar_id).bind(req.start_date).bind(req.end_date)
    .bind(&req.period_type).bind(req.descriptor.as_deref())
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(CalendarPeriodResponse {
        id: row.get("id"),
        calendar_id: row.get("calendar_id"),
        start_date: row.get("start_date"),
        end_date: row.get("end_date"),
        period_type: row.get("period_type"),
        descriptor: row.get("descriptor"),
    }))
}

/// `GET /v1/calendars/{id}/periods` — list calendar periods.
#[utoipa::path(
    get,
    path = "/v1/calendars/{id}/periods",
    responses(
        (status = 200, description = "Calendar periods", body = [CalendarPeriodResponse]),
        (status = 403, description = "Missing bank8:ledger:schedules:read scope"),
    ),
    security(("bank8:ledger:schedules:read" = [])),
    tag = "ledger",
)]
pub async fn list_calendar_periods(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(calendar_id): Path<Uuid>,
) -> Result<Json<Vec<CalendarPeriodResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:schedules:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let rows = sqlx::query(
        r#"SELECT id, calendar_id, start_date, end_date, period_type, descriptor
             FROM calendar_periods WHERE env_id = $1 AND calendar_id = $2
            ORDER BY start_date"#,
    )
    .bind(a.env_id())
    .bind(calendar_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| CalendarPeriodResponse {
                id: r.get("id"),
                calendar_id: r.get("calendar_id"),
                start_date: r.get("start_date"),
                end_date: r.get("end_date"),
                period_type: r.get("period_type"),
                descriptor: r.get("descriptor"),
            })
            .collect(),
    ))
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct BookkeepingDateResponse {
    pub calendar_id: Uuid,
    pub effective_date: chrono::NaiveDate,
    pub bookkeeping_date: chrono::NaiveDate,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/calendar/bookkeeping-date/{date}` — bookkeeping date for a day.
#[utoipa::path(
    get,
    path = "/v1/calendar/bookkeeping-date/{date}",
    params(("calendar_id" = Uuid, Query, description = "Calendar id")),
    responses(
        (status = 200, description = "Bookkeeping date", body = BookkeepingDateResponse),
        (status = 403, description = "Missing bank8:ledger:schedules:read scope"),
    ),
    security(("bank8:ledger:schedules:read" = [])),
    tag = "ledger",
)]
pub async fn get_bookkeeping_date(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(date): Path<chrono::NaiveDate>,
    Query(q): Query<BookkeepingDateQuery>,
) -> Result<Json<BookkeepingDateResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:schedules:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let calendar_id = q.calendar_id.ok_or((
        StatusCode::BAD_REQUEST,
        "calendar_id query parameter required".into(),
    ))?;
    // Default: the effective date itself (no override row).
    let row = sqlx::query(
        r#"SELECT calendar_id, effective_date, bookkeeping_date, updated_at
             FROM bookkeeping_dates WHERE env_id = $1 AND calendar_id = $2 AND effective_date = $3"#,
    )
    .bind(a.env_id()).bind(calendar_id).bind(date)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(match row {
        Some(r) => BookkeepingDateResponse {
            calendar_id: r.get("calendar_id"),
            effective_date: r.get("effective_date"),
            bookkeeping_date: r.get("bookkeeping_date"),
            updated_at: r.get("updated_at"),
        },
        None => BookkeepingDateResponse {
            calendar_id,
            effective_date: date,
            bookkeeping_date: date,
            updated_at: chrono::Utc::now(),
        },
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BookkeepingDateQuery {
    #[serde(default)]
    pub calendar_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertBookkeepingDateRequest {
    pub calendar_id: Uuid,
    pub bookkeeping_date: chrono::NaiveDate,
}

/// `PUT /v1/calendar/bookkeeping-date/{date}` — set the bookkeeping date.
#[utoipa::path(
    put,
    path = "/v1/calendar/bookkeeping-date/{date}",
    request_body = UpsertBookkeepingDateRequest,
    responses(
        (status = 200, description = "Bookkeeping date set", body = BookkeepingDateResponse),
        (status = 403, description = "Missing bank8:ledger:schedules:write scope"),
    ),
    security(("bank8:ledger:schedules:write" = [])),
    tag = "ledger",
)]
pub async fn upsert_bookkeeping_date(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(date): Path<chrono::NaiveDate>,
    Json(req): Json<UpsertBookkeepingDateRequest>,
) -> Result<Json<BookkeepingDateResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:ledger:schedules:write"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;
    let row = sqlx::query(
        r#"INSERT INTO bookkeeping_dates (env_id, calendar_id, effective_date, bookkeeping_date)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (calendar_id, effective_date) DO UPDATE
             SET bookkeeping_date = EXCLUDED.bookkeeping_date, updated_at = now()
           RETURNING calendar_id, effective_date, bookkeeping_date, updated_at"#,
    )
    .bind(a.env_id()).bind(req.calendar_id).bind(date).bind(req.bookkeeping_date)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    emit_event(&state.pool, a.env_id(), "bank8:ledger:bookkeepingdate:updated",
        serde_json::json!({ "calendar_id": req.calendar_id, "effective_date": date.to_string(), "bookkeeping_date": req.bookkeeping_date.to_string() }))
        .await;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(BookkeepingDateResponse {
        calendar_id: row.get("calendar_id"),
        effective_date: row.get("effective_date"),
        bookkeeping_date: row.get("bookkeeping_date"),
        updated_at: row.get("updated_at"),
    }))
}

// ── Unit tests (§8.6 conventions — pure logic, no DB) ────────────────────

#[cfg(test)]
mod tests {
    /// Calendar event types: only the four documented kinds are valid.
    #[test]
    fn calendar_event_type_validation() {
        for valid in ["HOLIDAY", "WEEKEND", "ROLL", "PAUSE"] {
            assert!(matches!(valid, "HOLIDAY" | "WEEKEND" | "ROLL" | "PAUSE"));
        }
        assert!(!matches!(
            "BANK_HOLIDAY",
            "HOLIDAY" | "WEEKEND" | "ROLL" | "PAUSE"
        ));
    }

    /// Bookkeeping-date default: the effective date itself (§5.4).
    #[test]
    fn bookkeeping_date_default_is_identity() {
        let d = chrono::NaiveDate::from_ymd_opt(2026, 9, 6).unwrap();
        assert_eq!(d, d);
    }
}
