use crate::config::BootstrapConfig;
use crate::{config::OidcConfig, error::AppError};
use async_trait::async_trait;
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

pub struct MembershipUpdate<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub email: Option<&'a str>,
    pub display_name: Option<&'a str>,
    pub roles: &'a [String],
}

#[async_trait]
pub trait TokenVerifier: Send + Sync {
    async fn verify(&self, token: &str) -> Result<Identity, AppError>;
}

pub struct OidcTokenVerifier {
    issuer: String,
    audience: String,
    algorithms: Vec<Algorithm>,
    jwks_uri: String,
    client: reqwest::Client,
    keys: RwLock<HashMap<String, DecodingKey>>,
}

impl OidcTokenVerifier {
    pub async fn new(config: &OidcConfig) -> anyhow::Result<Self> {
        let client = reqwest::Client::new();
        let jwks_uri = if let Some(uri) = &config.jwks_uri {
            uri.clone()
        } else {
            let endpoint = format!(
                "{}/.well-known/openid-configuration",
                config.issuer.trim_end_matches('/')
            );
            let metadata: serde_json::Value = client
                .get(endpoint)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            anyhow::ensure!(
                metadata["issuer"] == config.issuer,
                "OIDC discovery issuer mismatch"
            );
            metadata["jwks_uri"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("OIDC discovery has no jwks_uri"))?
                .to_owned()
        };
        let keys = fetch_decoding_keys(&client, &jwks_uri).await?;
        let algorithms = config
            .algorithms
            .iter()
            .map(|name| parse_algorithm(name))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self {
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            algorithms,
            jwks_uri,
            client,
            keys: RwLock::new(keys),
        })
    }

    async fn decoding_key(&self, kid: &str) -> Result<DecodingKey, AppError> {
        if let Some(key) = self.keys.read().await.get(kid).cloned() {
            return Ok(key);
        }
        let refreshed = fetch_decoding_keys(&self.client, &self.jwks_uri)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "failed to refresh OIDC signing keys");
                invalid_token()
            })?;
        let key = refreshed.get(kid).cloned().ok_or_else(invalid_token)?;
        *self.keys.write().await = refreshed;
        Ok(key)
    }
}

async fn fetch_decoding_keys(
    client: &reqwest::Client,
    jwks_uri: &str,
) -> anyhow::Result<HashMap<String, DecodingKey>> {
    let set: JwkSet = client
        .get(jwks_uri)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let mut keys = HashMap::new();
    for jwk in &set.keys {
        if let Some(kid) = &jwk.common.key_id {
            keys.insert(kid.clone(), DecodingKey::from_jwk(jwk)?);
        }
    }
    anyhow::ensure!(!keys.is_empty(), "OIDC JWKS contains no keyed signing keys");
    Ok(keys)
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    email: Option<String>,
    name: Option<String>,
    preferred_username: Option<String>,
    #[serde(rename = "exp")]
    _exp: usize,
}

#[async_trait]
impl TokenVerifier for OidcTokenVerifier {
    async fn verify(&self, token: &str) -> Result<Identity, AppError> {
        let header = decode_header(token).map_err(|_| invalid_token())?;
        if !self.algorithms.contains(&header.alg) {
            return Err(invalid_token());
        }
        let key = self
            .decoding_key(header.kid.as_deref().ok_or_else(invalid_token)?)
            .await?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        let data = decode::<Claims>(token, &key, &validation).map_err(|_| invalid_token())?;
        if data.claims.iss != self.issuer || data.claims.sub.is_empty() {
            return Err(invalid_token());
        }
        Ok(Identity {
            issuer: data.claims.iss,
            subject: data.claims.sub,
            email: data.claims.email,
            display_name: data.claims.name.or(data.claims.preferred_username),
        })
    }
}

#[derive(Clone)]
pub struct StaticTokenVerifier {
    identities: Arc<HashMap<String, Identity>>,
}
impl StaticTokenVerifier {
    pub fn new(identities: HashMap<String, Identity>) -> Self {
        Self {
            identities: Arc::new(identities),
        }
    }
}
#[async_trait]
impl TokenVerifier for StaticTokenVerifier {
    async fn verify(&self, token: &str) -> Result<Identity, AppError> {
        self.identities
            .get(token)
            .cloned()
            .ok_or_else(invalid_token)
    }
}

#[derive(Clone)]
pub struct AuthorizationService {
    pool: PgPool,
    verifier: Arc<dyn TokenVerifier>,
}

#[derive(Debug, Clone)]
pub struct AccessContext {
    pub identity: Identity,
    pub roles: Vec<String>,
    pub organization_id: Uuid,
    pub organization_name: String,
    pub workspace_name: String,
}

impl AuthorizationService {
    pub fn new(pool: PgPool, verifier: Arc<dyn TokenVerifier>) -> Self {
        Self { pool, verifier }
    }
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<Identity, AppError> {
        let value = headers
            .get("authorization")
            .and_then(|x| x.to_str().ok())
            .ok_or_else(|| {
                AppError::new(
                    StatusCode::UNAUTHORIZED,
                    "BEARER_TOKEN_REQUIRED",
                    "A Bearer access token is required.",
                )
            })?;
        let token = value
            .strip_prefix("Bearer ")
            .filter(|x| !x.trim().is_empty())
            .ok_or_else(|| {
                AppError::new(
                    StatusCode::UNAUTHORIZED,
                    "BEARER_TOKEN_REQUIRED",
                    "A Bearer access token is required.",
                )
            })?;
        self.verifier.verify(token.trim()).await
    }
    pub async fn authorize_workspace(
        &self,
        headers: &HeaderMap,
        workspace_id: Uuid,
        permission: &str,
    ) -> Result<AccessContext, AppError> {
        let identity = self.authenticate(headers).await?;
        let row = sqlx::query("SELECT o.id organization_id,o.name organization_name,w.name workspace_name,m.roles FROM oidc_principals p JOIN organization_memberships m ON m.principal_id=p.id AND m.status='active' JOIN organizations o ON o.id=m.organization_id AND o.status='active' JOIN workspaces w ON w.organization_id=o.id AND w.status='active' WHERE p.issuer=$1 AND p.subject=$2 AND w.id=$3")
            .bind(&identity.issuer).bind(&identity.subject).bind(workspace_id).fetch_optional(&self.pool).await?;
        let row = row.ok_or_else(|| {
            AppError::forbidden(
                "TENANT_ACCESS_DENIED",
                "The identity is not an active member of this workspace tenant.",
            )
        })?;
        let roles: Vec<String> = row.try_get("roles")?;
        if !roles
            .iter()
            .any(|role| permissions(role).contains(permission))
        {
            return Err(AppError::forbidden(
                "PERMISSION_DENIED",
                format!("Permission {permission} is required."),
            ));
        }
        self.touch(&identity).await?;
        Ok(AccessContext {
            identity,
            roles,
            organization_id: row.try_get("organization_id")?,
            organization_name: row.try_get("organization_name")?,
            workspace_name: row.try_get("workspace_name")?,
        })
    }
    pub async fn describe_identity(
        &self,
        headers: &HeaderMap,
    ) -> Result<serde_json::Value, AppError> {
        let identity = self.authenticate(headers).await?;
        let rows = sqlx::query("SELECT o.id organization_id,o.name organization_name,m.roles,w.id workspace_id,w.name workspace_name FROM oidc_principals p JOIN organization_memberships m ON m.principal_id=p.id AND m.status='active' JOIN organizations o ON o.id=m.organization_id AND o.status='active' JOIN workspaces w ON w.organization_id=o.id AND w.status='active' WHERE p.issuer=$1 AND p.subject=$2 ORDER BY o.name,w.name")
            .bind(&identity.issuer).bind(&identity.subject).fetch_all(&self.pool).await?;
        if rows.is_empty() {
            return Err(AppError::forbidden(
                "TENANT_ACCESS_DENIED",
                "No active Agentobe tenant membership was found.",
            ));
        }
        self.touch(&identity).await?;
        let workspaces: Vec<_> = rows.into_iter().map(|row| { let roles: Vec<String> = row.get("roles"); let perms: BTreeSet<_> = roles.iter().flat_map(|r| permissions(r)).collect(); serde_json::json!({"organizationId":row.get::<Uuid,_>("organization_id"),"organizationName":row.get::<String,_>("organization_name"),"workspaceId":row.get::<Uuid,_>("workspace_id"),"workspaceName":row.get::<String,_>("workspace_name"),"roles":roles,"permissions":perms}) }).collect();
        Ok(serde_json::json!({"identity":identity,"workspaces":workspaces}))
    }
    async fn touch(&self, identity: &Identity) -> Result<(), AppError> {
        sqlx::query("UPDATE oidc_principals SET last_seen_at=now() WHERE issuer=$1 AND subject=$2")
            .bind(&identity.issuer)
            .bind(&identity.subject)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
    pub async fn authorize_organization(
        &self,
        headers: &HeaderMap,
        organization_id: Uuid,
        permission: &str,
    ) -> Result<(Identity, Vec<String>), AppError> {
        let identity = self.authenticate(headers).await?;
        let row=sqlx::query("SELECT m.roles FROM oidc_principals p JOIN organization_memberships m ON m.principal_id=p.id AND m.status='active' JOIN organizations o ON o.id=m.organization_id AND o.status='active' WHERE p.issuer=$1 AND p.subject=$2 AND o.id=$3").bind(&identity.issuer).bind(&identity.subject).bind(organization_id).fetch_optional(&self.pool).await?.ok_or_else(||AppError::forbidden("TENANT_ACCESS_DENIED","Organization access denied."))?;
        let roles: Vec<String> = row.get("roles");
        if !roles
            .iter()
            .any(|role| permissions(role).contains(permission))
        {
            return Err(AppError::forbidden(
                "PERMISSION_DENIED",
                format!("Permission {permission} is required."),
            ));
        }
        self.touch(&identity).await?;
        Ok((identity, roles))
    }
    pub async fn list_memberships(
        &self,
        organization_id: Uuid,
    ) -> Result<serde_json::Value, AppError> {
        let rows=sqlx::query("SELECT p.id principal_id,p.issuer,p.subject,p.email,p.display_name,m.roles,m.status,m.created_at,m.updated_at FROM organization_memberships m JOIN oidc_principals p ON p.id=m.principal_id WHERE m.organization_id=$1 ORDER BY COALESCE(p.display_name,p.email,p.subject)").bind(organization_id).fetch_all(&self.pool).await?;
        let items:Vec<_>=rows.iter().map(|r|serde_json::json!({"principal_id":r.get::<Uuid,_>("principal_id"),"issuer":r.get::<String,_>("issuer"),"subject":r.get::<String,_>("subject"),"email":r.get::<Option<String>,_>("email"),"display_name":r.get::<Option<String>,_>("display_name"),"roles":r.get::<Vec<String>,_>("roles"),"status":r.get::<String,_>("status"),"created_at":r.get::<chrono::DateTime<Utc>,_>("created_at"),"updated_at":r.get::<chrono::DateTime<Utc>,_>("updated_at")})).collect();
        Ok(serde_json::json!({"items":items}))
    }
    pub async fn upsert_membership(
        &self,
        organization_id: Uuid,
        update: MembershipUpdate<'_>,
        actor_id: &str,
        actor_roles: &[String],
    ) -> Result<serde_json::Value, AppError> {
        let MembershipUpdate {
            issuer,
            subject,
            email,
            display_name,
            roles,
        } = update;
        if roles.is_empty()
            || !roles.iter().all(|r| {
                matches!(
                    r.as_str(),
                    "owner" | "admin" | "operator" | "auditor" | "runner" | "viewer"
                )
            })
        {
            return Err(AppError::bad(
                "REQUEST_VALIDATION_FAILED",
                "Invalid membership roles.",
            ));
        }
        let mut tx = self.pool.begin().await?;
        let principal:Uuid=sqlx::query_scalar("INSERT INTO oidc_principals(issuer,subject,email,display_name) VALUES($1,$2,$3,$4) ON CONFLICT(issuer,subject) DO UPDATE SET email=COALESCE(EXCLUDED.email,oidc_principals.email),display_name=COALESCE(EXCLUDED.display_name,oidc_principals.display_name) RETURNING id").bind(issuer).bind(subject).bind(email).bind(display_name).fetch_one(&mut *tx).await?;
        let existing:Option<Vec<String>>=sqlx::query_scalar("SELECT roles FROM organization_memberships WHERE organization_id=$1 AND principal_id=$2 FOR UPDATE").bind(organization_id).bind(principal).fetch_optional(&mut *tx).await?;
        let owner_acting = actor_roles.iter().any(|r| r == "owner");
        if (roles.iter().any(|r| r == "owner")
            || existing
                .as_ref()
                .is_some_and(|rs| rs.iter().any(|r| r == "owner")))
            && !owner_acting
        {
            return Err(AppError::forbidden(
                "OWNER_ROLE_REQUIRED",
                "Only an owner can grant or modify an owner membership.",
            ));
        }
        if existing
            .as_ref()
            .is_some_and(|rs| rs.iter().any(|r| r == "owner"))
            && !roles.iter().any(|r| r == "owner")
        {
            assert_another_owner(&mut tx, organization_id, principal).await?;
        }
        let row=sqlx::query("INSERT INTO organization_memberships(organization_id,principal_id,roles,status,created_by) VALUES($1,$2,$3,'active',$4) ON CONFLICT(organization_id,principal_id) DO UPDATE SET roles=EXCLUDED.roles,status='active',updated_at=now() RETURNING organization_id,roles,status,created_at,updated_at").bind(organization_id).bind(principal).bind(roles).bind(actor_id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(
            serde_json::json!({"organization_id":row.get::<Uuid,_>("organization_id"),"roles":row.get::<Vec<String>,_>("roles"),"status":row.get::<String,_>("status"),"created_at":row.get::<chrono::DateTime<Utc>,_>("created_at"),"updated_at":row.get::<chrono::DateTime<Utc>,_>("updated_at")}),
        )
    }
    pub async fn change_membership_state(
        &self,
        organization_id: Uuid,
        principal_id: Uuid,
        status: &str,
        actor_roles: &[String],
    ) -> Result<serde_json::Value, AppError> {
        if !matches!(status, "active" | "suspended") {
            return Err(AppError::bad(
                "REQUEST_VALIDATION_FAILED",
                "Invalid membership status.",
            ));
        }
        let mut tx = self.pool.begin().await?;
        let current:Vec<String>=sqlx::query_scalar("SELECT roles FROM organization_memberships WHERE organization_id=$1 AND principal_id=$2 FOR UPDATE").bind(organization_id).bind(principal_id).fetch_optional(&mut *tx).await?.ok_or_else(||AppError::not_found("MEMBERSHIP_NOT_FOUND","Membership not found."))?;
        if current.iter().any(|r| r == "owner") && !actor_roles.iter().any(|r| r == "owner") {
            return Err(AppError::forbidden(
                "OWNER_ROLE_REQUIRED",
                "Only an owner can change an owner membership.",
            ));
        }
        if status == "suspended" && current.iter().any(|r| r == "owner") {
            assert_another_owner(&mut tx, organization_id, principal_id).await?;
        }
        let row=sqlx::query("UPDATE organization_memberships SET status=$3,updated_at=now() WHERE organization_id=$1 AND principal_id=$2 RETURNING organization_id,principal_id,roles,status,created_at,updated_at").bind(organization_id).bind(principal_id).bind(status).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(
            serde_json::json!({"organization_id":row.get::<Uuid,_>("organization_id"),"principal_id":row.get::<Uuid,_>("principal_id"),"roles":row.get::<Vec<String>,_>("roles"),"status":row.get::<String,_>("status"),"created_at":row.get::<chrono::DateTime<Utc>,_>("created_at"),"updated_at":row.get::<chrono::DateTime<Utc>,_>("updated_at")}),
        )
    }
    pub async fn ensure_bootstrap_owner(
        &self,
        issuer: &str,
        bootstrap: &BootstrapConfig,
    ) -> Result<(), AppError> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)")
                .bind(bootstrap.organization_id)
                .fetch_one(&self.pool)
                .await?;
        if !exists {
            return Err(AppError::not_found(
                "ORGANIZATION_NOT_FOUND",
                "Bootstrap organization not found.",
            ));
        }
        let principal:Uuid=sqlx::query_scalar("INSERT INTO oidc_principals(issuer,subject,email,display_name) VALUES($1,$2,$3,$4) ON CONFLICT(issuer,subject) DO UPDATE SET email=COALESCE(EXCLUDED.email,oidc_principals.email),display_name=COALESCE(EXCLUDED.display_name,oidc_principals.display_name) RETURNING id").bind(issuer).bind(&bootstrap.subject).bind(&bootstrap.email).bind(&bootstrap.display_name).fetch_one(&self.pool).await?;
        sqlx::query("INSERT INTO organization_memberships(organization_id,principal_id,roles,status,created_by) VALUES($1,$2,ARRAY['owner']::text[],'active','bootstrap') ON CONFLICT(organization_id,principal_id) DO NOTHING").bind(bootstrap.organization_id).bind(principal).execute(&self.pool).await?;
        Ok(())
    }
}

async fn assert_another_owner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    excluded: Uuid,
) -> Result<(), AppError> {
    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM organization_memberships WHERE organization_id=$1 AND principal_id<>$2 AND status='active' AND roles@>ARRAY['owner']::text[]").bind(organization_id).bind(excluded).fetch_one(&mut **tx).await?;
    if count == 0 {
        Err(AppError::conflict(
            "LAST_OWNER_REQUIRED",
            "An organization must retain at least one active owner.",
        ))
    } else {
        Ok(())
    }
}

fn permissions(role: &str) -> BTreeSet<&'static str> {
    let all = [
        "workspace:read",
        "backup:write",
        "backup:verify",
        "contract:write",
        "source:control",
        "projection:write",
        "mission:write",
        "simulation:run",
        "ai-result:write",
        "audit:read",
        "membership:read",
        "membership:write",
    ];
    match role {
        "owner" | "admin" => all.into_iter().collect(),
        "operator" => [
            "workspace:read",
            "backup:write",
            "backup:verify",
            "source:control",
            "projection:write",
            "mission:write",
            "simulation:run",
        ]
        .into_iter()
        .collect(),
        "auditor" => [
            "workspace:read",
            "backup:verify",
            "audit:read",
            "membership:read",
        ]
        .into_iter()
        .collect(),
        "runner" => ["workspace:read", "ai-result:write", "simulation:run"]
            .into_iter()
            .collect(),
        "viewer" => ["workspace:read"].into_iter().collect(),
        _ => BTreeSet::new(),
    }
}
fn invalid_token() -> AppError {
    AppError::new(
        StatusCode::UNAUTHORIZED,
        "ACCESS_TOKEN_INVALID",
        "The OIDC access token is invalid or expired.",
    )
}
fn parse_algorithm(name: &str) -> anyhow::Result<Algorithm> {
    Ok(match name {
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        other => anyhow::bail!("unsupported OIDC algorithm {other}"),
    })
}
