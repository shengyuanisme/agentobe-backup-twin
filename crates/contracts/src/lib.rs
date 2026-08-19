use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const DEMO_WORKSPACE_ID: Uuid = Uuid::from_u128(0x00000000000040008000000000000001);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DataClass {
    D0,
    D1,
    D2,
    D3,
    D4,
}

impl DataClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::D0 => "D0",
            Self::D1 => "D1",
            Self::D2 => "D2",
            Self::D3 => "D3",
            Self::D4 => "D4",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Cursor {
    pub start: String,
    pub end: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EnterpriseEventInput {
    pub source_event_id: String,
    pub sequence: i64,
    pub event_type: String,
    pub entity_type: String,
    pub entity_id: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub classification: Vec<DataClass>,
    pub payload: Value,
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateBackupBatch {
    pub source: String,
    pub contract_version: String,
    pub schema_version: String,
    pub cursor: Cursor,
    pub trace_id: Option<Uuid>,
    pub events: Vec<EnterpriseEventInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateProjection {
    pub mission_id: String,
    pub runner_id: String,
    pub contract_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicationContractRules {
    pub entity: String,
    pub mode: String,
    pub allow: Vec<String>,
    pub tokenize: Vec<String>,
    pub deny: Vec<String>,
    pub simulation_use: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateReplicationContract {
    pub source: String,
    pub version: String,
    pub rules: ReplicationContractRules,
    pub freshness_slo_seconds: i32,
    pub retention_days: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeReplicationSourceState {
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiResultKind {
    SimulationEvent,
    Alert,
    Conclusion,
    Prediction,
    ActionProposal,
}

impl AiResultKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SimulationEvent => "simulation_event",
            Self::Alert => "alert",
            Self::Conclusion => "conclusion",
            Self::Prediction => "prediction",
            Self::ActionProposal => "action_proposal",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateAiResult {
    pub projection_id: Uuid,
    pub experiment_id: String,
    pub agent_version: String,
    pub tool_version: String,
    pub kind: AiResultKind,
    pub evidence_refs: Vec<String>,
    pub content: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MissionConstraints {
    pub prohibit_ticket_closure: bool,
    pub prohibit_external_messages: bool,
    pub max_p1_age_hours: f64,
    pub queue_capacity: BTreeMap<String, i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MissionBudget {
    pub max_branches: i32,
    pub max_steps_per_branch: i32,
    pub max_runtime_seconds: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateSimulationMission {
    pub name: String,
    pub objective: String,
    pub projection_id: Uuid,
    pub success_metric: String,
    pub guard_metric: String,
    pub constraints: MissionConstraints,
    pub budget: MissionBudget,
    pub tool_scope: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RunSimulationMission {
    pub requested_branches: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSimulationMissionState {
    pub status: String,
    pub reason: String,
}

pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(&normalize(value)).expect("JSON serialization")
}

pub fn sha256_value(value: &Value) -> String {
    sha256_bytes(canonical_json(value).as_bytes())
}
pub fn sha256_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn normalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
        Value::Object(map) => {
            let sorted: BTreeMap<_, _> = map
                .iter()
                .map(|(key, value)| (key.clone(), normalize(value)))
                .collect();
            serde_json::to_value(sorted).expect("normalized object")
        }
        other => other.clone(),
    }
}
