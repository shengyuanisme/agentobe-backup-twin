use agentobe_middleware_api::{
    auth::OidcTokenVerifier,
    build_router,
    config::Config,
    migrate,
    vault::{BlobStore, EncryptedSourceVault, FileBlobStore, SpacesBlobStore},
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let config = Config::from_env()?;
    migrate(&config.database_url).await?;
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&config.database_url)
        .await?;
    let verifier = Arc::new(OidcTokenVerifier::new(&config.oidc).await?);
    let auth =
        agentobe_middleware_api::auth::AuthorizationService::new(pool.clone(), verifier.clone());
    if let Some(bootstrap) = &config.bootstrap {
        auth.ensure_bootstrap_owner(&config.oidc.issuer, bootstrap)
            .await?;
    }
    let store: Arc<dyn BlobStore> = if config.vault.driver == "spaces" {
        Arc::new(
            SpacesBlobStore::new(
                required("SPACES_BUCKET")?,
                required("SPACES_REGION")?,
                required("SPACES_ACCESS_KEY_ID")?,
                required("SPACES_SECRET_ACCESS_KEY")?,
            )
            .await,
        )
    } else {
        Arc::new(FileBlobStore::new(config.vault.file_directory.clone()))
    };
    let vault = EncryptedSourceVault::new(
        store,
        &config.vault.master_key,
        config.vault.key_version.clone(),
    )?;
    let app = build_router(
        pool,
        verifier,
        config.projection_token_key,
        vault,
        &config.console_origins,
    );
    let listener = tokio::net::TcpListener::bind((config.host.as_str(), config.port)).await?;
    tracing::info!(address=%listener.local_addr()?,"Agentobe Rust middleware listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}
fn required(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("{key} is required when VAULT_DRIVER=spaces"))
}
async fn shutdown() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.expect("ctrl-c") };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("sigterm")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {_ = ctrl_c=>{},_ = terminate=>{}}
}
