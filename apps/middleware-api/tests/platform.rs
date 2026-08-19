use agentobe_contracts::DEMO_WORKSPACE_ID;
use agentobe_middleware_api::{
    auth::{Identity, StaticTokenVerifier},
    build_router, migrate,
    outbox::{OutboxMessage, OutboxPublisher, drain_once},
    vault::{EncryptedSourceVault, MemoryBlobStore},
};
use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;

#[tokio::test]
#[ignore = "requires AGENTOBE_TEST_DATABASE_URL pointing to an isolated disposable database"]
async fn rust_core_preserves_backup_auth_and_four_branch_simulation() {
    let database_url = std::env::var("AGENTOBE_TEST_DATABASE_URL")
        .expect("AGENTOBE_TEST_DATABASE_URL must point to an isolated disposable database");
    migrate(&database_url).await.unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .unwrap();
    setup(&pool).await;
    let verifier = StaticTokenVerifier::new(HashMap::from([
        ("admin-token".into(), identity("replicator-demo")),
        ("runner-token".into(), identity("shadow-runner-demo")),
        ("viewer-token".into(), identity("viewer-demo")),
        ("outsider-token".into(), identity("partner-outsider")),
    ]));
    let vault = EncryptedSourceVault::new(
        Arc::new(MemoryBlobStore::default()),
        "YWdlbnRvYmUtZGVtby12YXVsdC1rZXktMDAwMDAwMDA=",
        "test-v1".into(),
    )
    .unwrap();
    let app = build_router(
        pool.clone(),
        Arc::new(verifier),
        "test-projection-key".into(),
        vault,
        &[],
    );

    let unauth = call(
        &app,
        "GET",
        &format!("/v1/workspaces/{DEMO_WORKSPACE_ID}/backup-batches"),
        None,
        None,
    )
    .await;
    assert_eq!(unauth.0, StatusCode::UNAUTHORIZED);
    let seeded = call(
        &app,
        "POST",
        "/v1/demo/seed",
        Some("admin-token"),
        Some(json!({})),
    )
    .await;
    assert_eq!(seeded.0, StatusCode::CREATED, "{}", seeded.1);
    let batch = seeded.1["batch"]["id"].as_str().unwrap();
    assert_eq!(seeded.1["batch"]["recordCount"], 3);
    let restore = call(
        &app,
        "GET",
        &format!("/v1/workspaces/{DEMO_WORKSPACE_ID}/backup-batches/{batch}/restore-verification"),
        Some("admin-token"),
        None,
    )
    .await;
    assert_eq!(restore.1["status"], "healthy");
    assert_eq!(
        restore.1["expectedManifestHash"],
        restore.1["restoredManifestHash"]
    );
    let vault = call(
        &app,
        "GET",
        &format!("/v1/workspaces/{DEMO_WORKSPACE_ID}/backup-batches/{batch}/vault-verification"),
        Some("admin-token"),
        None,
    )
    .await;
    assert_eq!(vault.1["verification"]["status"], "healthy");
    let projection=call(&app,"POST",&format!("/v1/workspaces/{DEMO_WORKSPACE_ID}/backup-batches/{batch}/projections"),Some("admin-token"),Some(json!({"missionId":"rust-input","runnerId":"shadow-runner-demo","contractVersion":"v1"}))).await;
    assert_eq!(projection.0, StatusCode::CREATED, "{}", projection.1);
    assert!(projection.1.to_string().contains("tok_"));
    assert!(!projection.1.to_string().contains("customer-991"));
    let projection_id = projection.1["id"].as_str().unwrap();
    let mission=call(&app,"POST",&format!("/v1/workspaces/{DEMO_WORKSPACE_ID}/simulation-missions"),Some("admin-token"),Some(json!({"name":"Rust autonomous SLA exploration","objective":"Reduce projected SLA breaches with isolated shadow-only tools.","projectionId":projection_id,"successMetric":"sla_breach_rate","guardMetric":"escalation_rate","constraints":{"prohibitTicketClosure":true,"prohibitExternalMessages":true,"maxP1AgeHours":24,"queueCapacity":{"apac-general":1,"integrations":1,"overflow":2}},"budget":{"maxBranches":4,"maxStepsPerBranch":20,"maxRuntimeSeconds":60},"toolScope":["ticket.priority","ticket.queue","ticket.capacity"]}))).await;
    assert_eq!(mission.0, StatusCode::CREATED, "{}", mission.1);
    let mission_id = mission.1["id"].as_str().unwrap();
    let viewer = call(
        &app,
        "POST",
        &format!("/v1/workspaces/{DEMO_WORKSPACE_ID}/simulation-missions/{mission_id}/run"),
        Some("viewer-token"),
        Some(json!({"requestedBranches":4})),
    )
    .await;
    assert_eq!(viewer.0, StatusCode::FORBIDDEN);
    let run = call(
        &app,
        "POST",
        &format!("/v1/workspaces/{DEMO_WORKSPACE_ID}/simulation-missions/{mission_id}/run"),
        Some("admin-token"),
        Some(json!({"requestedBranches":4})),
    )
    .await;
    assert_eq!(run.0, StatusCode::OK, "{}", run.1);
    assert_eq!(run.1["status"], "completed");
    let branches = run.1["experiments"][0]["branches"].as_array().unwrap();
    assert_eq!(branches.len(), 4);
    assert!(
        branches.iter().all(|branch| branch["reproducible"] == true
            && !branch["steps"].as_array().unwrap().is_empty())
    );
    assert_eq!(
        run.1["experiments"][0]["summary"]["productionSideEffects"],
        0
    );
    let result_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ai_results WHERE experiment_id=$1")
            .bind(run.1["experiments"][0]["id"].as_str().unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(result_count, 4);
    let paused_source = call(
        &app,
        "POST",
        &format!("/v1/workspaces/{DEMO_WORKSPACE_ID}/replication-sources/ticketing-sandbox/state"),
        Some("viewer-token"),
        Some(json!({"status":"paused","reason":"must fail"})),
    )
    .await;
    assert_eq!(paused_source.0, StatusCode::FORBIDDEN);
    let sink = Sink::default();
    let (published, failed) = drain_once(&pool, &sink, 100).await.unwrap();
    assert!(published > 0);
    assert_eq!(failed, 0);
    assert_eq!(sink.0.lock().unwrap().len(), published);
    pool.close().await;
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = if let Some(value) = body {
        builder
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)}));
    (status, value)
}
fn identity(subject: &str) -> Identity {
    Identity {
        issuer: "https://identity.test.example".into(),
        subject: subject.into(),
        email: Some(format!("{subject}@example.test")),
        display_name: None,
    }
}

async fn setup(pool: &PgPool) {
    sqlx::query("TRUNCATE outbox_events,audit_events,simulation_branches,simulation_experiments,simulation_missions,ai_results,ai_projections,source_backup_objects,enterprise_events,backup_batches RESTART IDENTITY CASCADE").execute(pool).await.unwrap();
    sqlx::query("UPDATE replication_source_controls SET status='active',reason='rust test reset'")
        .execute(pool)
        .await
        .unwrap();
    for subject in [
        "replicator-demo",
        "shadow-runner-demo",
        "viewer-demo",
        "partner-outsider",
    ] {
        sqlx::query("INSERT INTO oidc_principals(issuer,subject,email) VALUES('https://identity.test.example',$1,$2) ON CONFLICT(issuer,subject) DO UPDATE SET email=EXCLUDED.email").bind(subject).bind(format!("{subject}@example.test")).execute(pool).await.unwrap();
    }
    sqlx::query("INSERT INTO organization_memberships(organization_id,principal_id,roles,status,created_by) SELECT '00000000-0000-4000-8000-000000000010',id,CASE subject WHEN 'replicator-demo' THEN ARRAY['owner']::text[] WHEN 'shadow-runner-demo' THEN ARRAY['runner']::text[] ELSE ARRAY['viewer']::text[] END,'active','rust-test' FROM oidc_principals WHERE issuer='https://identity.test.example' AND subject IN('replicator-demo','shadow-runner-demo','viewer-demo') ON CONFLICT(organization_id,principal_id) DO UPDATE SET roles=EXCLUDED.roles,status='active'").execute(pool).await.unwrap();
}

#[derive(Default)]
struct Sink(Mutex<Vec<OutboxMessage>>);
#[async_trait]
impl OutboxPublisher for Sink {
    async fn publish(&self, message: &OutboxMessage) -> anyhow::Result<()> {
        self.0.lock().unwrap().push(message.clone());
        Ok(())
    }
}
