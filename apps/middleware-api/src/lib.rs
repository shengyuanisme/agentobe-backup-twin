pub mod auth;
pub mod config;
pub mod error;
pub mod outbox;
pub mod store;
pub mod vault;

use agentobe_contracts::*;
use auth::{AuthorizationService, MembershipUpdate, TokenVerifier};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use error::AppError;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use store::Store;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use uuid::Uuid;
use vault::EncryptedSourceVault;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub auth: AuthorizationService,
    pub store: Store,
}

pub async fn migrate(database_url: &str) -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await?;
    sqlx::migrate!("./src/db/migrations").run(&pool).await?;
    pool.close().await;
    Ok(())
}

pub fn build_router(
    pool: PgPool,
    token_verifier: Arc<dyn TokenVerifier>,
    projection_token_key: String,
    vault: EncryptedSourceVault,
    origins: &[String],
) -> Router {
    let state = AppState {
        store: Store::new(pool.clone(), projection_token_key, vault),
        auth: AuthorizationService::new(pool.clone(), token_verifier),
        pool,
    };
    let origin_values: Vec<HeaderValue> = origins.iter().filter_map(|x| x.parse().ok()).collect();
    Router::new()
        .route("/health", get(health))
        .route("/docs", get(docs))
        .route("/v1/me", get(me))
        .route(
            "/v1/organizations/{organization_id}/memberships",
            get(list_memberships).post(upsert_membership),
        )
        .route(
            "/v1/organizations/{organization_id}/memberships/{principal_id}/state",
            post(change_membership_state),
        )
        .route("/v1/demo/seed", post(seed))
        .route(
            "/v1/workspaces/{workspace_id}/backup-batches",
            get(list_batches).post(create_batch),
        )
        .route(
            "/v1/workspaces/{workspace_id}/backup-batches/{batch_id}",
            get(get_batch),
        )
        .route(
            "/v1/workspaces/{workspace_id}/backup-batches/{batch_id}/vault-verification",
            get(verify_vault),
        )
        .route(
            "/v1/workspaces/{workspace_id}/backup-batches/{batch_id}/restore-verification",
            get(verify_restore),
        )
        .route(
            "/v1/workspaces/{workspace_id}/backup-batches/{batch_id}/projections",
            post(create_projection),
        )
        .route(
            "/v1/workspaces/{workspace_id}/replication-sources",
            get(list_sources),
        )
        .route(
            "/v1/workspaces/{workspace_id}/replication-sources/{source}/state",
            post(change_source),
        )
        .route(
            "/v1/workspaces/{workspace_id}/replication-contracts",
            get(list_contracts).post(create_contract),
        )
        .route(
            "/v1/workspaces/{workspace_id}/projections",
            get(list_projections),
        )
        .route(
            "/v1/workspaces/{workspace_id}/projections/{projection_id}",
            get(get_projection),
        )
        .route(
            "/v1/workspaces/{workspace_id}/ai-results",
            post(create_ai_result),
        )
        .route(
            "/v1/workspaces/{workspace_id}/traces/{trace_id}",
            get(get_trace),
        )
        .route(
            "/v1/workspaces/{workspace_id}/simulation-missions",
            get(list_missions).post(create_mission),
        )
        .route(
            "/v1/workspaces/{workspace_id}/simulation-missions/{mission_id}",
            get(get_mission),
        )
        .route(
            "/v1/workspaces/{workspace_id}/simulation-missions/{mission_id}/state",
            post(change_mission_state),
        )
        .route(
            "/v1/workspaces/{workspace_id}/simulation-missions/{mission_id}/run",
            post(run_mission),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origin_values))
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health(State(s): State<AppState>) -> Result<Json<Value>, AppError> {
    sqlx::query("SELECT 1").execute(&s.pool).await?;
    Ok(Json(
        json!({"status":"ok","service":"backup-simulation-middleware-rs"}),
    ))
}
async fn docs() -> impl IntoResponse {
    Json(
        json!({"openapi":"3.1.0","info":{"title":"Agentobe Backup & Simulation Middleware API (Rust)","version":"0.1.0"},"paths":{}}),
    )
}
async fn me(State(s): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, AppError> {
    Ok(Json(s.auth.describe_identity(&headers).await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MembershipBody {
    issuer: String,
    subject: String,
    email: Option<String>,
    display_name: Option<String>,
    roles: Vec<String>,
}
#[derive(Deserialize)]
struct StateBody {
    status: String,
}
async fn list_memberships(
    State(s): State<AppState>,
    Path(org): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    s.auth
        .authorize_organization(&headers, org, "membership:read")
        .await?;
    Ok(Json(s.auth.list_memberships(org).await?))
}
async fn upsert_membership(
    State(s): State<AppState>,
    Path(org): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<MembershipBody>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let (ctx, roles) = s
        .auth
        .authorize_organization(&headers, org, "membership:write")
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(
            s.auth
                .upsert_membership(
                    org,
                    MembershipUpdate {
                        issuer: &body.issuer,
                        subject: &body.subject,
                        email: body.email.as_deref(),
                        display_name: body.display_name.as_deref(),
                        roles: &body.roles,
                    },
                    &ctx.subject,
                    &roles,
                )
                .await?,
        ),
    ))
}
async fn change_membership_state(
    State(s): State<AppState>,
    Path((org, principal)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<StateBody>,
) -> Result<Json<Value>, AppError> {
    let (_, roles) = s
        .auth
        .authorize_organization(&headers, org, "membership:write")
        .await?;
    Ok(Json(
        s.auth
            .change_membership_state(org, principal, &body.status, &roles)
            .await?,
    ))
}

async fn seed(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let context = s
        .auth
        .authorize_workspace(&headers, DEMO_WORKSPACE_ID, "backup:write")
        .await?;
    let input = agentobe_ticketing_fixtures::synthetic_backup_batch();
    if let Some(batch) = s
        .store
        .find_batch_by_cursor(DEMO_WORKSPACE_ID, &input.source, &input.cursor.end)
        .await?
    {
        return Ok((
            StatusCode::OK,
            Json(json!({"workspaceId":DEMO_WORKSPACE_ID,"created":false,"batch":batch})),
        ));
    }
    let batch = s
        .store
        .create_backup_batch(DEMO_WORKSPACE_ID, &input, &context.identity.subject)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"workspaceId":DEMO_WORKSPACE_ID,"created":true,"batch":batch})),
    ))
}
async fn create_batch(
    State(s): State<AppState>,
    Path(workspace): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreateBackupBatch>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let c = s
        .auth
        .authorize_workspace(&headers, workspace, "backup:write")
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(
            s.store
                .create_backup_batch(workspace, &input, &c.identity.subject)
                .await?,
        ),
    ))
}
async fn list_batches(
    State(s): State<AppState>,
    Path(workspace): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    s.auth
        .authorize_workspace(&headers, workspace, "workspace:read")
        .await?;
    Ok(Json(s.store.list_backup_batches(workspace).await?))
}
async fn get_batch(
    State(s): State<AppState>,
    Path((workspace, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    s.auth
        .authorize_workspace(&headers, workspace, "workspace:read")
        .await?;
    Ok(Json(s.store.get_backup_batch(workspace, id).await?))
}
async fn verify_vault(
    State(s): State<AppState>,
    Path((workspace, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    s.auth
        .authorize_workspace(&headers, workspace, "backup:verify")
        .await?;
    Ok(Json(s.store.verify_vault(workspace, id).await?))
}
async fn verify_restore(
    State(s): State<AppState>,
    Path((workspace, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    s.auth
        .authorize_workspace(&headers, workspace, "backup:verify")
        .await?;
    Ok(Json(s.store.verify_restore(workspace, id).await?))
}
async fn list_sources(
    State(s): State<AppState>,
    Path(workspace): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    s.auth
        .authorize_workspace(&headers, workspace, "workspace:read")
        .await?;
    Ok(Json(s.store.list_sources(workspace).await?))
}
async fn change_source(
    State(s): State<AppState>,
    Path((workspace, source)): Path<(Uuid, String)>,
    headers: HeaderMap,
    Json(input): Json<ChangeReplicationSourceState>,
) -> Result<Json<Value>, AppError> {
    let c = s
        .auth
        .authorize_workspace(&headers, workspace, "source:control")
        .await?;
    Ok(Json(
        s.store
            .change_source_state(workspace, &source, &input, &c.identity.subject)
            .await?,
    ))
}
#[derive(Deserialize)]
struct ContractQuery {
    source: Option<String>,
}
async fn list_contracts(
    State(s): State<AppState>,
    Path(workspace): Path<Uuid>,
    Query(query): Query<ContractQuery>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    s.auth
        .authorize_workspace(&headers, workspace, "workspace:read")
        .await?;
    Ok(Json(
        s.store
            .list_contracts(workspace, query.source.as_deref())
            .await?,
    ))
}
async fn create_contract(
    State(s): State<AppState>,
    Path(workspace): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreateReplicationContract>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let c = s
        .auth
        .authorize_workspace(&headers, workspace, "contract:write")
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(
            s.store
                .create_contract(workspace, &input, &c.identity.subject)
                .await?,
        ),
    ))
}
async fn create_projection(
    State(s): State<AppState>,
    Path((workspace, batch)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<CreateProjection>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let c = s
        .auth
        .authorize_workspace(&headers, workspace, "projection:write")
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(
            s.store
                .create_projection(workspace, batch, &input, &c.identity.subject)
                .await?,
        ),
    ))
}
async fn list_projections(
    State(s): State<AppState>,
    Path(workspace): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    s.auth
        .authorize_workspace(&headers, workspace, "workspace:read")
        .await?;
    Ok(Json(s.store.list_projections(workspace).await?))
}
async fn get_projection(
    State(s): State<AppState>,
    Path((workspace, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    s.auth
        .authorize_workspace(&headers, workspace, "workspace:read")
        .await?;
    Ok(Json(s.store.get_projection(workspace, id).await?))
}
async fn create_ai_result(
    State(s): State<AppState>,
    Path(workspace): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreateAiResult>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let c = s
        .auth
        .authorize_workspace(&headers, workspace, "ai-result:write")
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(
            s.store
                .create_ai_result(workspace, &input, &c.identity.subject)
                .await?,
        ),
    ))
}
async fn get_trace(
    State(s): State<AppState>,
    Path((workspace, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    s.auth
        .authorize_workspace(&headers, workspace, "audit:read")
        .await?;
    Ok(Json(s.store.trace(workspace, id).await?))
}
async fn create_mission(
    State(s): State<AppState>,
    Path(workspace): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreateSimulationMission>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let c = s
        .auth
        .authorize_workspace(&headers, workspace, "mission:write")
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(
            s.store
                .create_mission(workspace, &input, &c.identity.subject)
                .await?,
        ),
    ))
}
async fn list_missions(
    State(s): State<AppState>,
    Path(workspace): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    s.auth
        .authorize_workspace(&headers, workspace, "workspace:read")
        .await?;
    Ok(Json(s.store.list_missions(workspace).await?))
}
async fn get_mission(
    State(s): State<AppState>,
    Path((workspace, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    s.auth
        .authorize_workspace(&headers, workspace, "workspace:read")
        .await?;
    Ok(Json(s.store.get_mission(workspace, id).await?))
}
async fn change_mission_state(
    State(s): State<AppState>,
    Path((workspace, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<ChangeSimulationMissionState>,
) -> Result<Json<Value>, AppError> {
    let c = s
        .auth
        .authorize_workspace(&headers, workspace, "mission:write")
        .await?;
    Ok(Json(
        s.store
            .change_mission_state(workspace, id, &input, &c.identity.subject)
            .await?,
    ))
}
async fn run_mission(
    State(s): State<AppState>,
    Path((workspace, id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<RunSimulationMission>,
) -> Result<Json<Value>, AppError> {
    let c = s
        .auth
        .authorize_workspace(&headers, workspace, "simulation:run")
        .await?;
    Ok(Json(
        s.store
            .run_mission(
                workspace,
                id,
                input.requested_branches,
                &c.identity.subject,
                &c.roles,
            )
            .await?,
    ))
}
