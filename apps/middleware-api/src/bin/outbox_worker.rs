use agentobe_middleware_api::{
    config::Config,
    migrate,
    outbox::{OutboxPublisher, StructuredLogPublisher, WebhookPublisher, drain_once},
};
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Config::from_env()?;
    migrate(&config.database_url).await?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;
    let publisher: Box<dyn OutboxPublisher> = match config.outbox_webhook_url {
        Some(url) => Box::new(WebhookPublisher::new(url)),
        None => Box::new(StructuredLogPublisher),
    };
    loop {
        match drain_once(&pool, publisher.as_ref(), 25).await {
            Ok((published, failed)) if published + failed > 0 => {
                tracing::info!(published, failed, "outbox drained")
            }
            Err(error) => tracing::error!(?error, "outbox drain failed"),
            _ => {}
        }
        tokio::time::sleep(std::time::Duration::from_millis(
            config.outbox_poll_interval_ms,
        ))
        .await;
    }
}
