use agentobe_contracts::{
    CreateBackupBatch, Cursor, DataClass, EnterpriseEventInput, sha256_value,
};
use serde_json::json;

pub fn synthetic_backup_batch() -> CreateBackupBatch {
    let rows = [
        (
            "demo-ticket-1842-created",
            "CS-1842",
            "2026-08-17T08:00:00Z",
            json!({"ticket_id":"CS-1842","state":"open","priority":"high","customer_tier":"enterprise","sla_due_at":"2026-08-17T14:00:00.000Z","tags":["regional-queue","backlog"],"queue":"apac-general","requester_id":"customer-991","created_at":"2026-08-17T07:10:00.000Z","updated_at":"2026-08-17T08:00:00.000Z"}),
        ),
        (
            "demo-ticket-1843-created",
            "CS-1843",
            "2026-08-17T08:01:00Z",
            json!({"ticket_id":"CS-1843","state":"open","priority":"normal","customer_tier":"growth","sla_due_at":"2026-08-18T08:00:00.000Z","tags":["billing-question"],"queue":"apac-general","requester_id":"customer-447","created_at":"2026-08-17T07:25:00.000Z","updated_at":"2026-08-17T08:01:00.000Z"}),
        ),
        (
            "demo-ticket-1844-created",
            "CS-1844",
            "2026-08-17T08:02:00Z",
            json!({"ticket_id":"CS-1844","state":"pending","priority":"normal","customer_tier":"enterprise","sla_due_at":"2026-08-17T18:00:00.000Z","tags":["integration"],"queue":"integrations","requester_id":"customer-118","created_at":"2026-08-17T06:55:00.000Z","updated_at":"2026-08-17T08:02:00.000Z"}),
        ),
    ];
    CreateBackupBatch {
        source: "ticketing-sandbox".into(),
        contract_version: "v1".into(),
        schema_version: "ticket-v1".into(),
        cursor: Cursor {
            start: "demo:1".into(),
            end: "demo:3".into(),
        },
        trace_id: None,
        events: rows
            .into_iter()
            .enumerate()
            .map(
                |(index, (source_id, entity_id, at, payload))| EnterpriseEventInput {
                    source_event_id: source_id.into(),
                    sequence: index as i64 + 1,
                    event_type: "ticket.snapshot".into(),
                    entity_type: "ticket".into(),
                    entity_id: entity_id.into(),
                    occurred_at: at.parse().unwrap(),
                    classification: vec![DataClass::D1, DataClass::D2],
                    checksum: Some(sha256_value(&payload)),
                    payload,
                },
            )
            .collect(),
    }
}
