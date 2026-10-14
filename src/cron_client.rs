// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Cron HTTP client — Ledger delegates all scheduling to Cron.
//! Ledger does NOT run its own scheduler. Instead, it creates schedules in
//! Cron via `POST /v1/schedules` and implements a proxy-back endpoint
//! `POST /v1/internal/schedules/run` that Cron calls when a schedule fires.
//! This module wraps the Cron REST API using a `Sentin8HttpClient` so that
//! `X-Sentin8-Correlation-Id` is propagated end-to-end.

use sentin8::middleware::http_client::Sentin8HttpClient;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct CronClient {
    base_url: String,
    auth_token: String,
    http: Sentin8HttpClient,
}

#[derive(Debug, Serialize)]
pub struct CreateCronSchedule {
    pub domain: String,
    pub schedule_type: String,
    pub cron_expression: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_config: Option<serde_json::Value>,
    #[serde(default = "default_max_retries")]
    pub max_retries: i32,
}

#[allow(dead_code)]
fn default_max_retries() -> i32 {
    3
}

#[derive(Debug, Deserialize)]
pub struct CronScheduleResponse {
    pub id: uuid::Uuid,
    pub domain: String,
    pub schedule_type: String,
    pub cron_expression: String,
    pub status: String,
    pub next_run_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CronJobResponse {
    pub id: uuid::Uuid,
    pub schedule_id: Option<uuid::Uuid>,
    pub job_type: String,
    pub status: String,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl CronClient {
    pub fn new(base_url: impl Into<String>, auth_token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            auth_token: auth_token.into(),
            http: Sentin8HttpClient::new(),
        }
    }

    /// `POST /v1/schedules` — create a schedule in Cron.
    pub async fn create_schedule(
        &self,
        req: &CreateCronSchedule,
    ) -> Result<CronScheduleResponse, String> {
        let resp = self
            .http
            .post(format!("{}/v1/schedules", self.base_url))
            .bearer_auth(&self.auth_token)
            .json(req)
            .send()
            .await
            .map_err(|e| format!("cron create schedule: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("cron HTTP {}", resp.status()));
        }
        resp.json().await.map_err(|e| format!("cron decode: {e}"))
    }

    /// `GET /v1/schedules` — list schedules from Cron.
    pub async fn list_schedules(&self) -> Result<Vec<CronScheduleResponse>, String> {
        let resp = self
            .http
            .get(format!("{}/v1/schedules", self.base_url))
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| format!("cron list schedules: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("cron HTTP {}", resp.status()));
        }
        resp.json().await.map_err(|e| format!("cron decode: {e}"))
    }

    /// `DELETE /v1/schedules/{id}` — delete a schedule in Cron.
    pub async fn delete_schedule(&self, id: &str) -> Result<(), String> {
        let resp = self
            .http
            .delete(format!("{}/v1/schedules/{}", self.base_url, id))
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| format!("cron delete: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("cron HTTP {}", resp.status()));
        }
        Ok(())
    }

    /// `POST /v1/schedules/{id}/pause` — pause a schedule.
    pub async fn pause_schedule(&self, id: &str) -> Result<(), String> {
        let resp = self
            .http
            .post(format!("{}/v1/schedules/{}/pause", self.base_url, id))
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| format!("cron pause: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("cron HTTP {}", resp.status()));
        }
        Ok(())
    }

    /// `POST /v1/schedules/{id}/resume` — resume a schedule.
    pub async fn resume_schedule(&self, id: &str) -> Result<(), String> {
        let resp = self
            .http
            .post(format!("{}/v1/schedules/{}/resume", self.base_url, id))
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| format!("cron resume: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("cron HTTP {}", resp.status()));
        }
        Ok(())
    }

    /// `GET /v1/jobs` — list jobs from Cron.
    pub async fn list_jobs(&self) -> Result<Vec<CronJobResponse>, String> {
        let resp = self
            .http
            .get(format!("{}/v1/jobs", self.base_url))
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| format!("cron list jobs: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("cron HTTP {}", resp.status()));
        }
        resp.json().await.map_err(|e| format!("cron decode: {e}"))
    }

    /// `POST /v1/jobs/{id}/retry` — retry a failed job in Cron.
    pub async fn retry_job(&self, id: &str) -> Result<CronJobResponse, String> {
        let resp = self
            .http
            .post(format!("{}/v1/jobs/{}/retry", self.base_url, id))
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| format!("cron retry job: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("cron HTTP {}", resp.status()));
        }
        resp.json().await.map_err(|e| format!("cron decode: {e}"))
    }

    /// `GET /v1/dlq` — list DLQ entries from Cron.
    pub async fn list_dlq(&self) -> Result<Vec<serde_json::Value>, String> {
        let resp = self
            .http
            .get(format!("{}/v1/dlq", self.base_url))
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| format!("cron list dlq: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("cron HTTP {}", resp.status()));
        }
        resp.json().await.map_err(|e| format!("cron decode: {e}"))
    }

    /// `POST /v1/dlq/{id}/republish` — republish a DLQ entry in Cron.
    pub async fn republish_dlq(&self, id: &str) -> Result<(), String> {
        let resp = self
            .http
            .post(format!("{}/v1/dlq/{}/republish", self.base_url, id))
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| format!("cron republish: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("cron HTTP {}", resp.status()));
        }
        Ok(())
    }
}
