// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Ledger
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Bus consumer — reacts to `sentin8:sys:service:updated` events.
//! Env-init for bank8-ledger is **event-driven**, not a synchronous RPC.
//! Sentin8:Sys emits `sentin8:sys:service:updated` to Sentin8:Bus (stream
//! family `sys`) whenever a service is enabled for an org/env. This
//! consumer subscribes to the `sys` stream family via SSE, drains
//! messages, and dispatches `sentin8:sys:service:updated` events to
//! [`seed_accounts::seed_for_service_event`], which seeds the standard set
//! of internal bank accounts when `service == "ledger"` and
//! `enabled == true`.
//! Uses the same SSE pattern as `sentin8/services/bff/src/subscribe/bus.rs`
//! — the `BusClient::sse_consume` method opens a long-lived
//! `text/event-stream` connection. Each `data:` line is a JSON
//! `sentin8::bus::contracts::Message`. ACKs are sent via `POST /v1/ack`.
//! Design: `services/ledger/DESIGN.md` §7
//! (Service Gates).

use std::time::Duration;

use futures_util::StreamExt;
use sqlx::PgPool;

use super::seed_accounts;

/// Consumer group name — identifies this ledger instance to Sentin8:Bus.
/// Using a stable group name means messages are load-balanced across ledger
/// replicas and a single message is only handled once per group.
const CONSUMER_GROUP: &str = "bank8:ledger:envinit";

/// Reconnect delay when the Bus SSE connection drops or an error occurs.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Spawn the Bus consumer background task. Called once from `server::serve`.
pub fn spawn(
    pool: PgPool,
    bus_client: sentin8::bus::client::BusClient,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(pool, bus_client).await;
    })
}

/// Run the consumer loop: connect to Bus SSE for the `sys` stream family,
/// read messages, dispatch relevant events, ACK on success, reconnect on
/// disconnect or error.
async fn run(pool: PgPool, bus_client: sentin8::bus::client::BusClient) {
    tracing::info!("ledger: bus env-init consumer started (consumer_group={CONSUMER_GROUP})");

    loop {
        match bus_client.sse_consume("sys", CONSUMER_GROUP).await {
            Ok(resp) => {
                tracing::info!("ledger: bus SSE connected to stream family 'sys'");
                sse_loop(&pool, &bus_client, resp).await;
                tracing::info!("ledger: bus SSE disconnected — reconnecting");
            }
            Err(e) => {
                tracing::warn!(error = %e, "ledger: bus SSE consume failed — reconnecting");
            }
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Process messages from a single Bus SSE connection until it drops.
async fn sse_loop(
    pool: &PgPool,
    bus_client: &sentin8::bus::client::BusClient,
    resp: reqwest::Response,
) {
    let mut stream = resp.bytes_stream();
    let mut buffer = String::new();

    while let Some(chunk_result) = stream.next().await {
        let chunk = match chunk_result {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "ledger: bus SSE stream error");
                return;
            }
        };

        // Append chunk to buffer and process complete SSE events.
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        // SSE events are separated by blank lines. Each event has `data:`
        // lines. Process all complete events in the buffer.
        while let Some(blank_pos) = buffer.find("\n\n") {
            let event_str = buffer[..blank_pos].to_string();
            buffer = buffer[blank_pos + 2..].to_string();

            // Extract the `data:` payload from the event.
            let data_line = event_str
                .lines()
                .filter_map(|l| l.strip_prefix("data:").map(|s| s.trim_start()))
                .collect::<Vec<_>>()
                .join("");
            if data_line.is_empty() {
                continue;
            }

            // Parse the message JSON.
            let msg: sentin8::bus::contracts::Message = match serde_json::from_str(&data_line) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(error = %e, "ledger: failed to parse SSE message");
                    continue;
                }
            };

            // Dispatch to the handler (full envelope — provenance
            // verification needs publisher_vertical, VDC-2).
            seed_accounts::seed_for_service_event(pool, &msg).await;

            // ACK the message.
            if let Err(e) = bus_client.ack("sys", CONSUMER_GROUP, &msg.message_id).await {
                tracing::warn!(error = %e, message_id = %msg.message_id, "ledger: ack failed");
            }
        }
    }
}
