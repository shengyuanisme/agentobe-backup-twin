use agentobe_middleware_api::{config::Config, migrate};
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    migrate(&config.database_url).await?;
    println!("Database migration complete.");
    Ok(())
}
