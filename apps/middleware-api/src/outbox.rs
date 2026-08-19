use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboxMessage {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub trace_id: Uuid,
    pub topic: String,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
    pub attempts: i32,
}

#[async_trait]
pub trait OutboxPublisher: Send + Sync {
    async fn publish(&self, message: &OutboxMessage) -> anyhow::Result<()>;
}
pub struct StructuredLogPublisher;
#[async_trait]
impl OutboxPublisher for StructuredLogPublisher {
    async fn publish(&self, message: &OutboxMessage) -> anyhow::Result<()> {
        tracing::info!(target:"agentobe.outbox", message=%serde_json::to_string(message)?, "outbox event");
        Ok(())
    }
}
pub struct WebhookPublisher {
    url: String,
    client: reqwest::Client,
}
impl WebhookPublisher {
    pub fn new(url: String) -> Self {
        Self {
            url,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap(),
        }
    }
}
#[async_trait]
impl OutboxPublisher for WebhookPublisher {
    async fn publish(&self, message: &OutboxMessage) -> anyhow::Result<()> {
        self.client
            .post(&self.url)
            .json(message)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

pub async fn drain_once(
    pool: &PgPool,
    publisher: &dyn OutboxPublisher,
    limit: i64,
) -> anyhow::Result<(usize, usize)> {
    let mut tx = pool.begin().await?;
    let rows = sqlx::query("SELECT id,workspace_id,trace_id,topic,payload,created_at,attempts FROM outbox_events WHERE published_at IS NULL AND next_attempt_at<=now() ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT $1").bind(limit).fetch_all(&mut *tx).await?;
    let mut published = 0;
    let mut failed = 0;
    for row in rows {
        let message = OutboxMessage {
            id: row.try_get("id")?,
            workspace_id: row.try_get("workspace_id")?,
            trace_id: row.try_get("trace_id")?,
            topic: row.try_get("topic")?,
            payload: row.try_get("payload")?,
            created_at: row.try_get("created_at")?,
            attempts: row.try_get("attempts")?,
        };
        match publisher.publish(&message).await {
            Ok(()) => {
                sqlx::query("UPDATE outbox_events SET published_at=now(),attempts=attempts+1,last_error=NULL WHERE id=$1").bind(message.id).execute(&mut *tx).await?;
                published += 1;
            }
            Err(error) => {
                let delay = 300_i32.min(2_i32.pow((message.attempts + 1).min(8) as u32));
                sqlx::query("UPDATE outbox_events SET attempts=attempts+1,last_error=$2,next_attempt_at=now()+($3::text||' seconds')::interval WHERE id=$1").bind(message.id).bind(error.to_string().chars().take(1000).collect::<String>()).bind(delay).execute(&mut *tx).await?;
                failed += 1;
            }
        }
    }
    tx.commit().await?;
    Ok((published, failed))
}
