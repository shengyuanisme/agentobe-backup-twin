use anyhow::{Context, Result};
use std::{env, path::PathBuf};
use uuid::Uuid;

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub projection_token_key: String,
    pub console_origins: Vec<String>,
    pub oidc: OidcConfig,
    pub bootstrap: Option<BootstrapConfig>,
    pub vault: VaultConfig,
    pub outbox_poll_interval_ms: u64,
    pub outbox_webhook_url: Option<String>,
}

#[derive(Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks_uri: Option<String>,
    pub algorithms: Vec<String>,
}
#[derive(Clone)]
pub struct BootstrapConfig {
    pub organization_id: Uuid,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
}
#[derive(Clone)]
pub struct VaultConfig {
    pub driver: String,
    pub master_key: String,
    pub key_version: String,
    pub file_directory: PathBuf,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bootstrap = match (
            env::var("AUTH_BOOTSTRAP_ORGANIZATION_ID").ok(),
            env::var("AUTH_BOOTSTRAP_SUBJECT").ok(),
        ) {
            (Some(organization_id), Some(subject)) if !subject.is_empty() => {
                Some(BootstrapConfig {
                    organization_id: organization_id
                        .parse()
                        .context("invalid AUTH_BOOTSTRAP_ORGANIZATION_ID")?,
                    subject,
                    email: nonempty("AUTH_BOOTSTRAP_EMAIL"),
                    display_name: nonempty("AUTH_BOOTSTRAP_DISPLAY_NAME"),
                })
            }
            _ => None,
        };
        Ok(Self {
            host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "4100".into())
                .parse()
                .context("invalid PORT")?,
            database_url: env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgres://agentobe:agentobe-local@127.0.0.1:54329/agentobe".into()
            }),
            projection_token_key: env::var("PROJECTION_TOKEN_KEY")
                .unwrap_or_else(|_| "agentobe-demo-projection-token-key".into()),
            console_origins: env::var("CONSOLE_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:4173,http://localhost:5173".into())
                .split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_owned)
                .collect(),
            oidc: OidcConfig {
                issuer: env::var("OIDC_ISSUER")
                    .unwrap_or_else(|_| "http://localhost:8080/realms/agentobe".into()),
                audience: env::var("OIDC_AUDIENCE").unwrap_or_else(|_| "agentobe-api".into()),
                jwks_uri: nonempty("OIDC_JWKS_URI"),
                algorithms: env::var("OIDC_ALLOWED_ALGORITHMS")
                    .unwrap_or_else(|_| "RS256".into())
                    .split(',')
                    .map(str::trim)
                    .map(str::to_owned)
                    .collect(),
            },
            bootstrap,
            vault: VaultConfig {
                driver: env::var("VAULT_DRIVER").unwrap_or_else(|_| "file".into()),
                master_key: env::var("VAULT_MASTER_KEY")
                    .unwrap_or_else(|_| "YWdlbnRvYmUtZGVtby12YXVsdC1rZXktMDAwMDAwMDA=".into()),
                key_version: env::var("VAULT_KEY_VERSION").unwrap_or_else(|_| "demo-v1".into()),
                file_directory: env::var("VAULT_FILE_DIR")
                    .unwrap_or_else(|_| "/tmp/agentobe-vault".into())
                    .into(),
            },
            outbox_poll_interval_ms: env::var("OUTBOX_POLL_INTERVAL_MS")
                .unwrap_or_else(|_| "1000".into())
                .parse()
                .context("invalid OUTBOX_POLL_INTERVAL_MS")?,
            outbox_webhook_url: nonempty("OUTBOX_WEBHOOK_URL"),
        })
    }
}

fn nonempty(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.is_empty())
}
