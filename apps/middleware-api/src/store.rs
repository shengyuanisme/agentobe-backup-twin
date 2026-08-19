use crate::{
    error::AppError,
    vault::{EncryptedSourceVault, VaultObjectMetadata},
};
use agentobe_contracts::*;
use agentobe_simulation_engine::{SimulationInput, run_ticket_simulation};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{
    collections::{BTreeSet, HashSet},
    sync::Arc,
};
use uuid::Uuid;

#[derive(Clone)]
pub struct Store {
    pub pool: PgPool,
    projection_token_key: Arc<String>,
    vault: EncryptedSourceVault,
}

impl Store {
    pub fn new(pool: PgPool, projection_token_key: String, vault: EncryptedSourceVault) -> Self {
        Self {
            pool,
            projection_token_key: Arc::new(projection_token_key),
            vault,
        }
    }

    pub async fn find_batch_by_cursor(
        &self,
        workspace_id: Uuid,
        source: &str,
        cursor_end: &str,
    ) -> Result<Option<Value>, AppError> {
        Ok(sqlx::query(
            "SELECT * FROM backup_batches WHERE workspace_id=$1 AND source=$2 AND cursor_end=$3",
        )
        .bind(workspace_id)
        .bind(source)
        .bind(cursor_end)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| public_batch(&row)))
    }

    pub async fn create_backup_batch(
        &self,
        workspace_id: Uuid,
        input: &CreateBackupBatch,
        actor_id: &str,
    ) -> Result<Value, AppError> {
        validate_backup_input(input)?;
        let batch_id = Uuid::new_v4();
        let mut tx = self.pool.begin().await?;
        let workspace = sqlx::query("SELECT status FROM workspaces WHERE id=$1 FOR SHARE")
            .bind(workspace_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::not_found("WORKSPACE_NOT_FOUND", "Workspace not found."))?;
        if workspace.get::<String, _>("status") != "active" {
            return Err(AppError::conflict(
                "WORKSPACE_STOPPED",
                "Workspace ingestion is stopped.",
            ));
        }
        if let Some(control)=sqlx::query("SELECT status FROM replication_source_controls WHERE workspace_id=$1 AND source=$2 FOR SHARE").bind(workspace_id).bind(&input.source).fetch_optional(&mut *tx).await?
            && control.get::<String,_>("status")=="paused"
        {
            return Err(AppError::conflict("REPLICATION_SOURCE_PAUSED","Replication source is paused."));
        }
        let rules = self
            .contract_rules(
                &mut tx,
                workspace_id,
                &input.source,
                &input.contract_version,
            )
            .await?;
        let classifications = validate_events(&input.events, &rules)?;
        let trace_id = input.trace_id.unwrap_or_else(Uuid::new_v4);
        let sealed_at = Utc::now();
        let manifest_events:Vec<_>=input.events.iter().map(|event| json!({"sourceEventId":event.source_event_id,"sequence":event.sequence,"eventType":event.event_type,"entityType":event.entity_type,"entityId":event.entity_id,"occurredAt":event.occurred_at,"classification":event.classification.iter().map(DataClass::as_str).collect::<Vec<_>>(),"checksum":sha256_value(&event.payload)})).collect();
        let manifest = json!({"format":"agentobe.backup-manifest.v1","workspaceId":workspace_id,"source":input.source,"contractVersion":input.contract_version,"schemaVersion":input.schema_version,"cursor":input.cursor,"recordCount":input.events.len(),"classifications":classifications,"events":manifest_events});
        let manifest_hash = sha256_value(&manifest);
        let source_value = serde_json::to_value(input).unwrap();
        let vault_metadata=self.vault.put(workspace_id,batch_id,&json!({"format":"agentobe.source-backup.v1","workspaceId":workspace_id,"batchId":batch_id,"source":input.source,"contractVersion":input.contract_version,"schemaVersion":input.schema_version,"cursor":input.cursor,"events":source_value["events"]})).await?;
        let inserted=sqlx::query("INSERT INTO backup_batches(id,workspace_id,trace_id,source,contract_version,schema_version,cursor_start,cursor_end,status,manifest,manifest_hash,record_count,classifications,sealed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'sealed',$9,$10,$11,$12,$13) RETURNING *")
            .bind(batch_id).bind(workspace_id).bind(trace_id).bind(&input.source).bind(&input.contract_version).bind(&input.schema_version).bind(&input.cursor.start).bind(&input.cursor.end).bind(&manifest).bind(&manifest_hash).bind(input.events.len() as i32).bind(&classifications).bind(sealed_at).fetch_one(&mut *tx).await;
        let inserted = match inserted {
            Ok(row) => row,
            Err(error) => {
                self.vault.delete(&vault_metadata.object_key).await;
                return Err(map_unique(
                    error,
                    "DUPLICATE_BACKUP_BATCH",
                    "This source cursor or event was already ingested.",
                ));
            }
        };
        for event in &input.events {
            let classes: Vec<_> = event
                .classification
                .iter()
                .map(|x| x.as_str().to_owned())
                .collect();
            sqlx::query("INSERT INTO enterprise_events(id,workspace_id,backup_batch_id,source_event_id,sequence,event_type,entity_type,entity_id,occurred_at,classification,payload,payload_checksum) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)").bind(Uuid::new_v4()).bind(workspace_id).bind(batch_id).bind(&event.source_event_id).bind(event.sequence).bind(&event.event_type).bind(&event.entity_type).bind(&event.entity_id).bind(event.occurred_at).bind(classes).bind(&event.payload).bind(sha256_value(&event.payload)).execute(&mut *tx).await.map_err(|error|map_unique(error,"DUPLICATE_BACKUP_BATCH","This source cursor or event was already ingested."))?;
        }
        insert_vault_metadata(&mut tx, workspace_id, batch_id, &vault_metadata).await?;
        append_event(&mut tx,AuditEvent{workspace_id,trace_id,plane:"enterprise",actor_id,event_type:"backup.batch.sealed",object_type:"backup_batch",object_id:&batch_id.to_string(),classification:&classifications,metadata:json!({"manifestHash":manifest_hash,"recordCount":input.events.len(),"vaultCiphertextHash":vault_metadata.ciphertext_hash,"vaultKeyVersion":vault_metadata.key_version})}).await?;
        tx.commit().await?;
        Ok(public_batch(&inserted))
    }

    async fn contract_rules(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        source: &str,
        version: &str,
    ) -> Result<ReplicationContractRules, AppError> {
        let row=sqlx::query("SELECT rules FROM replication_contracts WHERE workspace_id=$1 AND source=$2 AND version=$3 AND active=true").bind(workspace_id).bind(source).bind(version).fetch_optional(&mut **tx).await?.ok_or_else(||AppError::not_found("REPLICATION_CONTRACT_NOT_FOUND","Active replication contract not found."))?;
        let value: Value = row.get("rules");
        serde_json::from_value(value).map_err(|_| {
            AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Invalid replication contract in storage.",
            )
        })
    }

    pub async fn list_backup_batches(&self, workspace_id: Uuid) -> Result<Value, AppError> {
        let rows = sqlx::query(
            "SELECT * FROM backup_batches WHERE workspace_id=$1 ORDER BY created_at DESC",
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(json!({"items":rows.iter().map(public_batch).collect::<Vec<_>>()}))
    }
    pub async fn get_backup_batch(
        &self,
        workspace_id: Uuid,
        batch_id: Uuid,
    ) -> Result<Value, AppError> {
        let row = sqlx::query("SELECT * FROM backup_batches WHERE id=$1 AND workspace_id=$2")
            .bind(batch_id)
            .bind(workspace_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| {
                AppError::not_found("BACKUP_BATCH_NOT_FOUND", "Backup batch not found.")
            })?;
        Ok(public_batch(&row))
    }
    pub async fn list_sources(&self, workspace_id: Uuid) -> Result<Value, AppError> {
        let rows=sqlx::query("SELECT c.workspace_id,c.source,c.status,c.reason,c.version,c.updated_by,c.updated_at,COUNT(rc.id)::int contract_count,MAX(rc.created_at) latest_contract_at FROM replication_source_controls c LEFT JOIN replication_contracts rc ON rc.workspace_id=c.workspace_id AND rc.source=c.source WHERE c.workspace_id=$1 GROUP BY c.workspace_id,c.source,c.status,c.reason,c.version,c.updated_by,c.updated_at ORDER BY c.source").bind(workspace_id).fetch_all(&self.pool).await?;
        Ok(json!({"items":rows.iter().map(public_source).collect::<Vec<_>>()}))
    }
    pub async fn list_contracts(
        &self,
        workspace_id: Uuid,
        source: Option<&str>,
    ) -> Result<Value, AppError> {
        let rows=sqlx::query("SELECT id,workspace_id,source,version,rules,freshness_slo_seconds,retention_days,created_by,created_at FROM replication_contracts WHERE workspace_id=$1 AND ($2::text IS NULL OR source=$2) ORDER BY source,created_at DESC").bind(workspace_id).bind(source).fetch_all(&self.pool).await?;
        Ok(json!({"items":rows.iter().map(public_contract).collect::<Vec<_>>()}))
    }
    pub async fn create_contract(
        &self,
        workspace_id: Uuid,
        input: &CreateReplicationContract,
        actor_id: &str,
    ) -> Result<Value, AppError> {
        validate_contract(input)?;
        let mut tx = self.pool.begin().await?;
        if sqlx::query("SELECT id FROM workspaces WHERE id=$1")
            .bind(workspace_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_none()
        {
            return Err(AppError::not_found(
                "WORKSPACE_NOT_FOUND",
                "Workspace not found.",
            ));
        }
        let id = Uuid::new_v4();
        let rules = serde_json::to_value(&input.rules).unwrap();
        let inserted=sqlx::query("INSERT INTO replication_contracts(id,workspace_id,source,version,rules,freshness_slo_seconds,retention_days,active,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,true,$8) RETURNING id,workspace_id,source,version,rules,freshness_slo_seconds,retention_days,created_by,created_at").bind(id).bind(workspace_id).bind(&input.source).bind(&input.version).bind(rules).bind(input.freshness_slo_seconds).bind(input.retention_days).bind(actor_id).fetch_one(&mut *tx).await.map_err(|e|map_unique(e,"CONTRACT_VERSION_EXISTS","Replication contract version already exists."))?;
        sqlx::query("INSERT INTO replication_source_controls(workspace_id,source,status,reason,updated_by) VALUES($1,$2,'active','Source activated with first contract',$3) ON CONFLICT(workspace_id,source) DO NOTHING").bind(workspace_id).bind(&input.source).bind(actor_id).execute(&mut *tx).await?;
        append_event(
            &mut tx,
            AuditEvent {
                workspace_id,
                trace_id: Uuid::new_v4(),
                plane: "control",
                actor_id,
                event_type: "replication.contract.created",
                object_type: "replication_contract",
                object_id: &id.to_string(),
                classification: &["D1".into()],
                metadata: json!({"source":input.source,"version":input.version}),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(public_contract(&inserted))
    }
    pub async fn change_source_state(
        &self,
        workspace_id: Uuid,
        source: &str,
        input: &ChangeReplicationSourceState,
        actor_id: &str,
    ) -> Result<Value, AppError> {
        if !matches!(input.status.as_str(), "active" | "paused") || input.reason.len() < 3 {
            return Err(AppError::bad(
                "REQUEST_VALIDATION_FAILED",
                "Invalid replication source state.",
            ));
        }
        let mut tx = self.pool.begin().await?;
        let row=sqlx::query("UPDATE replication_source_controls SET status=$3,reason=$4,version=version+1,updated_by=$5,updated_at=now() WHERE workspace_id=$1 AND source=$2 RETURNING workspace_id,source,status,reason,version,updated_by,updated_at").bind(workspace_id).bind(source).bind(&input.status).bind(&input.reason).bind(actor_id).fetch_optional(&mut *tx).await?.ok_or_else(||AppError::not_found("REPLICATION_SOURCE_NOT_FOUND","Replication source not found."))?;
        let trace = Uuid::new_v4();
        append_event(
            &mut tx,
            AuditEvent {
                workspace_id,
                trace_id: trace,
                plane: "control",
                actor_id,
                event_type: if input.status == "paused" {
                    "replication.source.paused"
                } else {
                    "replication.source.resumed"
                },
                object_type: "replication_source",
                object_id: source,
                classification: &["D1".into()],
                metadata: json!({"reason":input.reason,"version":row.get::<i64,_>("version")}),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(public_source_control(&row))
    }

    pub async fn create_projection(
        &self,
        workspace_id: Uuid,
        batch_id: Uuid,
        input: &CreateProjection,
        actor_id: &str,
    ) -> Result<Value, AppError> {
        validate_projection(input)?;
        let mut tx = self.pool.begin().await?;
        let batch =
            sqlx::query("SELECT * FROM backup_batches WHERE id=$1 AND workspace_id=$2 FOR SHARE")
                .bind(batch_id)
                .bind(workspace_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| {
                    AppError::not_found("BACKUP_BATCH_NOT_FOUND", "Backup batch not found.")
                })?;
        if batch.get::<String, _>("status") != "sealed" {
            return Err(AppError::conflict(
                "BACKUP_BATCH_NOT_HEALTHY",
                "Only a sealed backup batch can be projected.",
            ));
        }
        let rules = self
            .contract_rules(
                &mut tx,
                workspace_id,
                &batch.get::<String, _>("source"),
                &input.contract_version,
            )
            .await?;
        let events = sqlx::query(
            "SELECT * FROM enterprise_events WHERE backup_batch_id=$1 ORDER BY sequence",
        )
        .bind(batch_id)
        .fetch_all(&mut *tx)
        .await?;
        let mut tickets = Vec::new();
        for event in events {
            let classes: Vec<String> = event.get("classification");
            if classes.iter().any(|x| x == "D3" || x == "D4") {
                return Err(AppError::unprocessable(
                    "PROJECTION_CLASSIFICATION_BLOCKED",
                    "D3/D4 records cannot enter the default AI projection.",
                ));
            }
            let payload: Value = event.get("payload");
            let mut projected = serde_json::Map::new();
            if let Some(object) = payload.as_object() {
                for (key, value) in object {
                    if rules.allow.contains(key) && !rules.deny.contains(key) {
                        projected.insert(
                            key.clone(),
                            if rules.tokenize.contains(key) {
                                json!(self.tokenize(
                                    workspace_id,
                                    value.as_str().unwrap_or(&value.to_string())
                                ))
                            } else {
                                value.clone()
                            },
                        );
                    }
                }
            }
            projected.insert("_lineage".into(),json!({"sourceEventId":event.get::<String,_>("source_event_id"),"sourceChecksum":event.get::<String,_>("payload_checksum"),"backupBatchId":batch_id}));
            tickets.push(Value::Object(projected));
        }
        let payload = json!({"sourceBatchId":batch_id,"sourceManifestHash":batch.get::<String,_>("manifest_hash"),"missionId":input.mission_id,"runnerId":input.runner_id,"contractVersion":input.contract_version,"tickets":tickets});
        let projection_hash = sha256_value(&payload);
        let id = Uuid::new_v4();
        let version:i32=sqlx::query_scalar("SELECT COALESCE(MAX(version),0)::int+1 FROM ai_projections WHERE backup_batch_id=$1 AND mission_id=$2 AND runner_id=$3").bind(batch_id).bind(&input.mission_id).bind(&input.runner_id).fetch_one(&mut *tx).await?;
        let trace_id: Uuid = batch.get("trace_id");
        let inserted=sqlx::query("INSERT INTO ai_projections(id,workspace_id,backup_batch_id,trace_id,mission_id,runner_id,contract_version,version,status,payload,projection_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'sealed',$9,$10) RETURNING *").bind(id).bind(workspace_id).bind(batch_id).bind(trace_id).bind(&input.mission_id).bind(&input.runner_id).bind(&input.contract_version).bind(version).bind(&payload).bind(&projection_hash).fetch_one(&mut *tx).await?;
        append_event(&mut tx,AuditEvent{workspace_id,trace_id,plane:"shadow",actor_id,event_type:"ai.projection.sealed",object_type:"ai_projection",object_id:&id.to_string(),classification:&["D1".into(),"D2".into()],metadata:json!({"backupBatchId":batch_id,"projectionHash":projection_hash,"version":version})}).await?;
        tx.commit().await?;
        Ok(public_projection(&inserted))
    }
    pub async fn list_projections(&self, workspace_id: Uuid) -> Result<Value, AppError> {
        let rows = sqlx::query(
            "SELECT * FROM ai_projections WHERE workspace_id=$1 ORDER BY created_at DESC",
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(json!({"items":rows.iter().map(public_projection).collect::<Vec<_>>()}))
    }
    pub async fn get_projection(&self, workspace_id: Uuid, id: Uuid) -> Result<Value, AppError> {
        let row = sqlx::query("SELECT * FROM ai_projections WHERE id=$1 AND workspace_id=$2")
            .bind(id)
            .bind(workspace_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| {
                AppError::not_found("PROJECTION_NOT_FOUND", "AI projection not found.")
            })?;
        Ok(public_projection(&row))
    }
    fn tokenize(&self, workspace_id: Uuid, value: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.projection_token_key.as_bytes()).unwrap();
        mac.update(format!("{workspace_id}:{value}").as_bytes());
        format!("tok_{}", hex(&mac.finalize().into_bytes())[..24].to_owned())
    }

    pub async fn create_ai_result(
        &self,
        workspace_id: Uuid,
        input: &CreateAiResult,
        actor_id: &str,
    ) -> Result<Value, AppError> {
        validate_ai_result(input)?;
        let mut tx = self.pool.begin().await?;
        let projection =
            sqlx::query("SELECT * FROM ai_projections WHERE id=$1 AND workspace_id=$2 FOR SHARE")
                .bind(input.projection_id)
                .bind(workspace_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| {
                    AppError::not_found("PROJECTION_NOT_FOUND", "AI projection not found.")
                })?;
        if projection.get::<String, _>("runner_id") != actor_id {
            return Err(AppError::forbidden(
                "RUNNER_IDENTITY_MISMATCH",
                "Runner identity cannot write to this projection.",
            ));
        }
        let content_bytes = canonical_json(&input.content).len();
        if content_bytes > 65_536 {
            return Err(AppError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "AI_RESULT_TOO_LARGE",
                "Inline AI result exceeds 64 KiB.",
            ));
        }
        let payload: Value = projection.get("payload");
        let valid: HashSet<String> = payload["tickets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| t["ticket_id"].as_str())
            .map(|id| format!("ticket:{id}"))
            .collect();
        let mut reasons = content_quarantine_reasons(&input.content);
        reasons.extend(
            input
                .evidence_refs
                .iter()
                .filter(|r| !valid.contains(*r))
                .map(|r| format!("unknown evidence reference: {r}")),
        );
        let status = if !reasons.is_empty() {
            "quarantined"
        } else if matches!(input.kind, AiResultKind::ActionProposal) {
            "pending_compilation"
        } else {
            "recorded"
        };
        let id = Uuid::new_v4();
        let hash = sha256_value(&input.content);
        let row=sqlx::query("INSERT INTO ai_results(id,workspace_id,backup_batch_id,projection_id,trace_id,experiment_id,agent_version,tool_version,kind,status,evidence_refs,content,content_hash,quarantine_reasons) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *").bind(id).bind(workspace_id).bind(projection.get::<Uuid,_>("backup_batch_id")).bind(input.projection_id).bind(projection.get::<Uuid,_>("trace_id")).bind(&input.experiment_id).bind(&input.agent_version).bind(&input.tool_version).bind(input.kind.as_str()).bind(status).bind(&input.evidence_refs).bind(&input.content).bind(&hash).bind(&reasons).fetch_one(&mut *tx).await?;
        append_event(&mut tx,AuditEvent{workspace_id,trace_id:projection.get("trace_id"),plane:"shadow",actor_id,event_type:if status=="quarantined"{"ai.result.quarantined"}else{"ai.result.recorded"},object_type:"ai_result",object_id:&id.to_string(),classification:&["D1".into()],metadata:json!({"projectionId":input.projection_id,"kind":input.kind.as_str(),"status":status,"contentHash":hash})}).await?;
        tx.commit().await?;
        Ok(public_ai_result(&row))
    }

    pub async fn verify_restore(
        &self,
        workspace_id: Uuid,
        batch_id: Uuid,
    ) -> Result<Value, AppError> {
        let batch = sqlx::query("SELECT * FROM backup_batches WHERE id=$1 AND workspace_id=$2")
            .bind(batch_id)
            .bind(workspace_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| {
                AppError::not_found("BACKUP_BATCH_NOT_FOUND", "Backup batch not found.")
            })?;
        let events = sqlx::query(
            "SELECT * FROM enterprise_events WHERE backup_batch_id=$1 ORDER BY sequence",
        )
        .bind(batch_id)
        .fetch_all(&self.pool)
        .await?;
        let failures: Vec<String> = events
            .iter()
            .filter(|e| {
                let p: Value = e.get("payload");
                sha256_value(&p) != e.get::<String, _>("payload_checksum")
            })
            .map(|e| e.get("source_event_id"))
            .collect();
        let manifest_events:Vec<_>=events.iter().map(|event|json!({"sourceEventId":event.get::<String,_>("source_event_id"),"sequence":event.get::<i64,_>("sequence"),"eventType":event.get::<String,_>("event_type"),"entityType":event.get::<String,_>("entity_type"),"entityId":event.get::<String,_>("entity_id"),"occurredAt":event.get::<DateTime<Utc>,_>("occurred_at"),"classification":event.get::<Vec<String>,_>("classification"),"checksum":event.get::<String,_>("payload_checksum")})).collect();
        let manifest = json!({"format":"agentobe.backup-manifest.v1","workspaceId":workspace_id,"source":batch.get::<String,_>("source"),"contractVersion":batch.get::<String,_>("contract_version"),"schemaVersion":batch.get::<String,_>("schema_version"),"cursor":{"start":batch.get::<String,_>("cursor_start"),"end":batch.get::<String,_>("cursor_end")},"recordCount":events.len(),"classifications":batch.get::<Vec<String>,_>("classifications"),"events":manifest_events});
        let restored_hash = sha256_value(&manifest);
        let expected: String = batch.get("manifest_hash");
        let tickets: Value = Value::Object(
            events
                .iter()
                .map(|e| {
                    (
                        e.get::<String, _>("entity_id"),
                        e.get::<Value, _>("payload"),
                    )
                })
                .collect(),
        );
        Ok(
            json!({"batchId":batch_id,"status":if failures.is_empty()&&restored_hash==expected{"healthy"}else{"failed"},"recordCount":events.len(),"checksumFailures":failures,"expectedManifestHash":expected,"restoredManifestHash":restored_hash,"restoredStateHash":sha256_value(&tickets)}),
        )
    }

    pub async fn verify_vault(
        &self,
        workspace_id: Uuid,
        batch_id: Uuid,
    ) -> Result<Value, AppError> {
        let row=sqlx::query("SELECT object_key,storage_driver,encryption_algorithm,key_wrap_algorithm,key_version,plaintext_hash,ciphertext_hash,size_bytes FROM source_backup_objects WHERE workspace_id=$1 AND backup_batch_id=$2").bind(workspace_id).bind(batch_id).fetch_optional(&self.pool).await?.ok_or_else(||AppError::not_found("VAULT_OBJECT_NOT_FOUND","Encrypted source backup object not found."))?;
        let metadata = VaultObjectMetadata {
            object_key: row.get("object_key"),
            storage_driver: row.get("storage_driver"),
            encryption_algorithm: row.get("encryption_algorithm"),
            key_wrap_algorithm: row.get("key_wrap_algorithm"),
            key_version: row.get("key_version"),
            plaintext_hash: row.get("plaintext_hash"),
            ciphertext_hash: row.get("ciphertext_hash"),
            size_bytes: row.get("size_bytes"),
        };
        let verification = self.vault.verify(&metadata).await?;
        Ok(json!({"batchId":batch_id,"object":metadata,"verification":verification}))
    }
    pub async fn trace(&self, workspace_id: Uuid, trace_id: Uuid) -> Result<Value, AppError> {
        let rows=sqlx::query("SELECT id,trace_id,plane,actor_id,event_type,object_type,object_id,classification,metadata,created_at FROM audit_events WHERE workspace_id=$1 AND trace_id=$2 ORDER BY created_at,id").bind(workspace_id).bind(trace_id).fetch_all(&self.pool).await?;
        let events:Vec<_>=rows.iter().map(|r|json!({"id":r.get::<Uuid,_>("id"),"trace_id":r.get::<Uuid,_>("trace_id"),"plane":r.get::<String,_>("plane"),"actor_id":r.get::<String,_>("actor_id"),"event_type":r.get::<String,_>("event_type"),"object_type":r.get::<String,_>("object_type"),"object_id":r.get::<String,_>("object_id"),"classification":r.get::<Vec<String>,_>("classification"),"metadata":r.get::<Value,_>("metadata"),"created_at":r.get::<DateTime<Utc>,_>("created_at")})).collect();
        Ok(json!({"workspaceId":workspace_id,"traceId":trace_id,"events":events}))
    }

    pub async fn create_mission(
        &self,
        workspace_id: Uuid,
        input: &CreateSimulationMission,
        actor_id: &str,
    ) -> Result<Value, AppError> {
        validate_mission(input)?;
        let mut tx = self.pool.begin().await?;
        let projection=sqlx::query("SELECT p.* FROM ai_projections p JOIN backup_batches b ON b.id=p.backup_batch_id WHERE p.id=$1 AND p.workspace_id=$2 AND p.status='sealed' AND b.status='sealed' FOR SHARE OF p,b").bind(input.projection_id).bind(workspace_id).fetch_optional(&mut *tx).await?.ok_or_else(||AppError::unprocessable("SIMULATION_INPUT_NOT_READY","Mission requires a sealed projection from a healthy backup batch."))?;
        let id = Uuid::new_v4();
        let row=sqlx::query("INSERT INTO simulation_missions(id,workspace_id,projection_id,backup_batch_id,trace_id,name,objective,success_metric,guard_metric,constraints,budget,tool_scope,owner_id,runner_id,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'ready') RETURNING *").bind(id).bind(workspace_id).bind(input.projection_id).bind(projection.get::<Uuid,_>("backup_batch_id")).bind(projection.get::<Uuid,_>("trace_id")).bind(&input.name).bind(&input.objective).bind(&input.success_metric).bind(&input.guard_metric).bind(serde_json::to_value(&input.constraints).unwrap()).bind(serde_json::to_value(&input.budget).unwrap()).bind(&input.tool_scope).bind(actor_id).bind(projection.get::<String,_>("runner_id")).fetch_one(&mut *tx).await?;
        append_event(&mut tx,AuditEvent{workspace_id,trace_id:projection.get("trace_id"),plane:"shadow",actor_id,event_type:"simulation.mission.created",object_type:"simulation_mission",object_id:&id.to_string(),classification:&["D1".into()],metadata:json!({"projectionId":input.projection_id,"inputHash":projection.get::<String,_>("projection_hash")})}).await?;
        tx.commit().await?;
        Ok(public_mission(&row))
    }
    pub async fn list_missions(&self, workspace_id: Uuid) -> Result<Value, AppError> {
        let rows = sqlx::query(
            "SELECT * FROM simulation_missions WHERE workspace_id=$1 ORDER BY created_at DESC",
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(json!({"items":rows.iter().map(public_mission).collect::<Vec<_>>()}))
    }
    pub async fn get_mission(
        &self,
        workspace_id: Uuid,
        mission_id: Uuid,
    ) -> Result<Value, AppError> {
        let mission =
            sqlx::query("SELECT * FROM simulation_missions WHERE id=$1 AND workspace_id=$2")
                .bind(mission_id)
                .bind(workspace_id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| {
                    AppError::not_found(
                        "SIMULATION_MISSION_NOT_FOUND",
                        "Simulation mission not found.",
                    )
                })?;
        let experiments = sqlx::query(
            "SELECT * FROM simulation_experiments WHERE mission_id=$1 ORDER BY attempt DESC",
        )
        .bind(mission_id)
        .fetch_all(&self.pool)
        .await?;
        let mut values = Vec::new();
        for experiment in experiments {
            let id: Uuid = experiment.get("id");
            let branches=sqlx::query("SELECT id,workspace_id,experiment_id,name,strategy,ordinal,status,confidence::float8 confidence,assumptions,blind_spots,metrics,metric_delta,replay_steps,shadow_state,state_hash,reproducible,created_at FROM simulation_branches WHERE experiment_id=$1 ORDER BY ordinal").bind(id).fetch_all(&self.pool).await?;
            values.push(public_experiment(
                &experiment,
                branches.iter().map(public_branch).collect(),
            ));
        }
        let mut value = public_mission(&mission);
        value["experiments"] = Value::Array(values);
        Ok(value)
    }
    pub async fn change_mission_state(
        &self,
        workspace_id: Uuid,
        mission_id: Uuid,
        input: &ChangeSimulationMissionState,
        actor_id: &str,
    ) -> Result<Value, AppError> {
        if !matches!(input.status.as_str(), "ready" | "paused" | "cancelled")
            || input.reason.len() < 3
        {
            return Err(AppError::bad(
                "REQUEST_VALIDATION_FAILED",
                "Invalid mission state.",
            ));
        }
        let mut tx = self.pool.begin().await?;
        let current = sqlx::query(
            "SELECT * FROM simulation_missions WHERE id=$1 AND workspace_id=$2 FOR UPDATE",
        )
        .bind(mission_id)
        .bind(workspace_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            AppError::not_found(
                "SIMULATION_MISSION_NOT_FOUND",
                "Simulation mission not found.",
            )
        })?;
        let status: String = current.get("status");
        let allowed = (status == "ready"
            && matches!(input.status.as_str(), "paused" | "cancelled"))
            || (status == "paused" && matches!(input.status.as_str(), "ready" | "cancelled"));
        if !allowed {
            return Err(AppError::conflict(
                "MISSION_STATE_TRANSITION_REJECTED",
                "Mission state transition is not allowed.",
            ));
        }
        let row=sqlx::query("UPDATE simulation_missions SET status=$3,status_reason=$4,updated_at=now() WHERE id=$1 AND workspace_id=$2 RETURNING *").bind(mission_id).bind(workspace_id).bind(&input.status).bind(&input.reason).fetch_one(&mut *tx).await?;
        append_event(
            &mut tx,
            AuditEvent {
                workspace_id,
                trace_id: current.get("trace_id"),
                plane: "shadow",
                actor_id,
                event_type: if input.status == "ready" {
                    "simulation.mission.ready"
                } else if input.status == "paused" {
                    "simulation.mission.paused"
                } else {
                    "simulation.mission.cancelled"
                },
                object_type: "simulation_mission",
                object_id: &mission_id.to_string(),
                classification: &["D1".into()],
                metadata: json!({"previousStatus":status,"reason":input.reason}),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(public_mission(&row))
    }

    pub async fn run_mission(
        &self,
        workspace_id: Uuid,
        mission_id: Uuid,
        requested: Option<i32>,
        actor_id: &str,
        actor_roles: &[String],
    ) -> Result<Value, AppError> {
        let mut tx = self.pool.begin().await?;
        let mission = sqlx::query(
            "SELECT * FROM simulation_missions WHERE id=$1 AND workspace_id=$2 FOR UPDATE",
        )
        .bind(mission_id)
        .bind(workspace_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            AppError::not_found(
                "SIMULATION_MISSION_NOT_FOUND",
                "Simulation mission not found.",
            )
        })?;
        if mission.get::<String, _>("status") != "ready" {
            return Err(AppError::conflict(
                "SIMULATION_MISSION_NOT_READY",
                "Only a ready mission can start a new experiment.",
            ));
        }
        let runner_id: String = mission.get("runner_id");
        let operator = actor_roles
            .iter()
            .any(|role| matches!(role.as_str(), "owner" | "admin" | "operator"));
        if !operator && actor_id != runner_id {
            return Err(AppError::forbidden(
                "RUNNER_IDENTITY_MISMATCH",
                "Only the designated shadow runner can execute this mission.",
            ));
        }
        let projection=sqlx::query("SELECT * FROM ai_projections WHERE id=$1 AND workspace_id=$2 AND status='sealed' FOR SHARE").bind(mission.get::<Uuid,_>("projection_id")).bind(workspace_id).fetch_optional(&mut *tx).await?.ok_or_else(||AppError::conflict("SIMULATION_PROJECTION_REVOKED","The fixed mission projection is no longer available."))?;
        let budget: MissionBudget =
            serde_json::from_value(mission.get("budget")).map_err(|_| {
                AppError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Invalid mission budget.",
                )
            })?;
        let constraints: MissionConstraints = serde_json::from_value(mission.get("constraints"))
            .map_err(|_| {
                AppError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Invalid mission constraints.",
                )
            })?;
        let branches = requested.unwrap_or(4.min(budget.max_branches));
        if branches < 3 || branches > budget.max_branches || branches > 4 {
            return Err(AppError::unprocessable(
                "SIMULATION_BUDGET_EXCEEDED",
                "Requested branches exceed the mission budget or the three-branch minimum.",
            ));
        }
        let payload: Value = projection.get("payload");
        let tickets: Vec<Value> = payload["tickets"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|ticket| ticket["ticket_id"].is_string())
            .collect();
        let projection_hash: String = projection.get("projection_hash");
        let tool_scope: Vec<String> = mission.get("tool_scope");
        let started = Utc::now();
        let results = run_ticket_simulation(SimulationInput {
            tickets: &tickets,
            constraints: &constraints,
            budget: &budget,
            tool_scope: &tool_scope,
            branch_count: branches,
            projection_hash: &projection_hash,
        })
        .map_err(|message| AppError::unprocessable("SIMULATION_BUDGET_EXCEEDED", message))?;
        let attempt:i32=sqlx::query_scalar("SELECT COALESCE(MAX(attempt),0)::int+1 FROM simulation_experiments WHERE mission_id=$1").bind(mission_id).fetch_one(&mut *tx).await?;
        let experiment_id = Uuid::new_v4();
        let summary = json!({"branchCount":results.len(),"completedBranches":results.iter().filter(|x|x.status=="completed").count(),"reproducibleBranches":results.iter().filter(|x|x.reproducible).count(),"productionSideEffects":0});
        let experiment_status = if results.iter().all(|x| x.status == "completed") {
            "completed"
        } else {
            "inconclusive"
        };
        sqlx::query("INSERT INTO simulation_experiments(id,workspace_id,mission_id,projection_id,trace_id,attempt,status,requested_branches,agent_version,tool_version,input_hash,summary,started_at,completed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)").bind(experiment_id).bind(workspace_id).bind(mission_id).bind(projection.get::<Uuid,_>("id")).bind(mission.get::<Uuid,_>("trace_id")).bind(attempt).bind(experiment_status).bind(branches).bind("agentobe-shadow-runner-rs/0.1").bind("ticket-simulator-rs/0.1").bind(&projection_hash).bind(&summary).bind(started).bind(Utc::now()).execute(&mut *tx).await?;
        for (ordinal, branch) in results.iter().enumerate() {
            let branch_id = Uuid::new_v4();
            sqlx::query("INSERT INTO simulation_branches(id,workspace_id,experiment_id,name,strategy,ordinal,status,confidence,assumptions,blind_spots,metrics,metric_delta,replay_steps,shadow_state,state_hash,reproducible) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)").bind(branch_id).bind(workspace_id).bind(experiment_id).bind(&branch.name).bind(&branch.strategy).bind(ordinal as i32+1).bind(&branch.status).bind(branch.confidence).bind(serde_json::to_value(&branch.assumptions).unwrap()).bind(serde_json::to_value(&branch.blind_spots).unwrap()).bind(serde_json::to_value(&branch.metrics).unwrap()).bind(serde_json::to_value(&branch.delta).unwrap()).bind(serde_json::to_value(&branch.steps).unwrap()).bind(serde_json::to_value(&branch.shadow_state).unwrap()).bind(&branch.state_hash).bind(branch.reproducible).execute(&mut *tx).await?;
            let content = json!({"missionId":mission_id,"experimentId":experiment_id,"branchId":branch_id,"strategy":branch.strategy,"confidence":branch.confidence,"assumptions":branch.assumptions,"blindSpots":branch.blind_spots,"metrics":branch.metrics,"delta":branch.delta,"reproducible":branch.reproducible});
            let evidence: Vec<String> = tickets
                .iter()
                .filter_map(|t| t["ticket_id"].as_str())
                .map(|id| format!("ticket:{id}"))
                .collect();
            sqlx::query("INSERT INTO ai_results(id,workspace_id,backup_batch_id,projection_id,trace_id,experiment_id,agent_version,tool_version,kind,status,evidence_refs,content,content_hash,quarantine_reasons) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'prediction','recorded',$9,$10,$11,'{}')").bind(Uuid::new_v4()).bind(workspace_id).bind(projection.get::<Uuid,_>("backup_batch_id")).bind(projection.get::<Uuid,_>("id")).bind(projection.get::<Uuid,_>("trace_id")).bind(experiment_id.to_string()).bind("agentobe-shadow-runner-rs/0.1").bind("ticket-simulator-rs/0.1").bind(evidence).bind(&content).bind(sha256_value(&content)).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE simulation_missions SET status='completed',status_reason=NULL,updated_at=now() WHERE id=$1").bind(mission_id).execute(&mut *tx).await?;
        append_event(&mut tx,AuditEvent{workspace_id,trace_id:mission.get("trace_id"),plane:"shadow",actor_id:&runner_id,event_type:"simulation.experiment.completed",object_type:"simulation_experiment",object_id:&experiment_id.to_string(),classification:&["D1".into(),"D2".into()],metadata:json!({"missionId":mission_id,"requestedBy":actor_id,"branchCount":branches,"inputHash":projection_hash,"productionSideEffects":0})}).await?;
        tx.commit().await?;
        self.get_mission(workspace_id, mission_id).await
    }
}

struct AuditEvent<'a> {
    workspace_id: Uuid,
    trace_id: Uuid,
    plane: &'a str,
    actor_id: &'a str,
    event_type: &'a str,
    object_type: &'a str,
    object_id: &'a str,
    classification: &'a [String],
    metadata: Value,
}
async fn append_event(
    tx: &mut Transaction<'_, Postgres>,
    event: AuditEvent<'_>,
) -> Result<(), AppError> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO audit_events(id,workspace_id,trace_id,plane,actor_id,event_type,object_type,object_id,classification,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)").bind(id).bind(event.workspace_id).bind(event.trace_id).bind(event.plane).bind(event.actor_id).bind(event.event_type).bind(event.object_type).bind(event.object_id).bind(event.classification).bind(&event.metadata).execute(&mut **tx).await?;
    let mut payload = event.metadata;
    if let Some(map) = payload.as_object_mut() {
        map.insert("eventId".into(), json!(id));
        map.insert("objectType".into(), json!(event.object_type));
        map.insert("objectId".into(), json!(event.object_id));
    }
    sqlx::query(
        "INSERT INTO outbox_events(id,workspace_id,trace_id,topic,payload) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(event.workspace_id)
    .bind(event.trace_id)
    .bind(event.event_type)
    .bind(payload)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
async fn insert_vault_metadata(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
    batch_id: Uuid,
    m: &VaultObjectMetadata,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO source_backup_objects(id,workspace_id,backup_batch_id,object_key,storage_driver,encryption_algorithm,key_wrap_algorithm,key_version,plaintext_hash,ciphertext_hash,size_bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)").bind(Uuid::new_v4()).bind(workspace_id).bind(batch_id).bind(&m.object_key).bind(&m.storage_driver).bind(&m.encryption_algorithm).bind(&m.key_wrap_algorithm).bind(&m.key_version).bind(&m.plaintext_hash).bind(&m.ciphertext_hash).bind(m.size_bytes).execute(&mut **tx).await?;
    Ok(())
}

fn validate_backup_input(input: &CreateBackupBatch) -> Result<(), AppError> {
    if input.source.is_empty() || input.events.is_empty() || input.events.len() > 1000 {
        return Err(AppError::bad(
            "REQUEST_VALIDATION_FAILED",
            "Invalid backup batch.",
        ));
    }
    Ok(())
}
fn validate_events(
    events: &[EnterpriseEventInput],
    rules: &ReplicationContractRules,
) -> Result<Vec<String>, AppError> {
    let mut ordered = events.to_vec();
    ordered.sort_by_key(|e| e.sequence);
    for pair in ordered.windows(2) {
        if pair[1].sequence != pair[0].sequence + 1 {
            return Err(AppError::unprocessable(
                "EVENT_SEQUENCE_GAP",
                "Event sequence must be contiguous.",
            )
            .detail(json!({"previous":pair[0].sequence,"current":pair[1].sequence})));
        }
    }
    let mut classes = BTreeSet::new();
    for event in ordered {
        for class in &event.classification {
            classes.insert(class.as_str().to_owned());
            if matches!(class, DataClass::D4) {
                return Err(AppError::unprocessable(
                    "D4_SECRET_REJECTED",
                    "D4-classified events are prohibited.",
                ));
            }
        }
        assert_no_secrets(&event.payload)?;
        let keys: Vec<_> = event
            .payload
            .as_object()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        let denied: Vec<_> = keys
            .iter()
            .filter(|k| rules.deny.contains(*k))
            .cloned()
            .collect();
        let outside: Vec<_> = keys
            .iter()
            .filter(|k| !rules.allow.contains(*k))
            .cloned()
            .collect();
        if !denied.is_empty() || !outside.is_empty() {
            return Err(AppError::unprocessable(
                "REPLICATION_CONTRACT_VIOLATION",
                "Event contains fields outside the active replication contract.",
            )
            .detail(json!({"denied":denied,"outsideContract":outside})));
        }
        let hash = sha256_value(&event.payload);
        if event
            .checksum
            .as_ref()
            .is_some_and(|expected| expected != &hash)
        {
            return Err(AppError::unprocessable(
                "CHECKSUM_MISMATCH",
                "Event checksum does not match its canonical payload.",
            ));
        }
    }
    Ok(classes.into_iter().collect())
}
fn validate_contract(input: &CreateReplicationContract) -> Result<(), AppError> {
    if input.rules.entity != "ticket"
        || input.rules.mode != "snapshot_plus_events"
        || input.rules.allow.is_empty()
        || input.rules.deny.is_empty()
        || input.freshness_slo_seconds < 30
        || input.retention_days < 1
    {
        return Err(AppError::bad(
            "REQUEST_VALIDATION_FAILED",
            "Invalid replication contract.",
        ));
    }
    let overlap: Vec<_> = input
        .rules
        .allow
        .iter()
        .filter(|x| input.rules.deny.contains(*x))
        .collect();
    let invalid: Vec<_> = input
        .rules
        .tokenize
        .iter()
        .filter(|x| !input.rules.allow.contains(*x))
        .collect();
    let secret: Vec<_> = input
        .rules
        .allow
        .iter()
        .filter(|x| secret_name(x))
        .collect();
    if !overlap.is_empty() || !invalid.is_empty() || !secret.is_empty() {
        return Err(AppError::unprocessable(
            "INVALID_REPLICATION_CONTRACT",
            "Replication field rules are inconsistent or unsafe.",
        ));
    }
    Ok(())
}
fn validate_projection(input: &CreateProjection) -> Result<(), AppError> {
    if input.mission_id.is_empty()
        || input.runner_id.is_empty()
        || input.contract_version.is_empty()
    {
        Err(AppError::bad(
            "REQUEST_VALIDATION_FAILED",
            "Invalid projection request.",
        ))
    } else {
        Ok(())
    }
}
fn validate_ai_result(input: &CreateAiResult) -> Result<(), AppError> {
    if input.experiment_id.is_empty() || input.evidence_refs.is_empty() {
        Err(AppError::bad(
            "REQUEST_VALIDATION_FAILED",
            "Invalid AI result.",
        ))
    } else {
        Ok(())
    }
}
fn validate_mission(input: &CreateSimulationMission) -> Result<(), AppError> {
    let metric = |x: &str| {
        matches!(
            x,
            "sla_breach_rate" | "average_queue_age_hours" | "escalation_rate" | "open_workload"
        )
    };
    let allowed = |x: &str| matches!(x, "ticket.priority" | "ticket.queue" | "ticket.capacity");
    if input.name.len() < 3
        || input.objective.len() < 10
        || !metric(&input.success_metric)
        || !metric(&input.guard_metric)
        || input.budget.max_branches < 3
        || input.budget.max_branches > 4
        || input.budget.max_steps_per_branch < 1
        || input.tool_scope.is_empty()
        || !input.tool_scope.iter().all(|x| allowed(x))
    {
        return Err(AppError::bad(
            "REQUEST_VALIDATION_FAILED",
            "Invalid simulation mission.",
        ));
    }
    Ok(())
}
fn assert_no_secrets(value: &Value) -> Result<(), AppError> {
    if let Some(map) = value.as_object()
        && map.keys().any(|key| secret_name(key))
    {
        return Err(AppError::unprocessable(
            "D4_SECRET_REJECTED",
            "Secret fields are prohibited.",
        ));
    }
    Ok(())
}
fn secret_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase().replace(['-', '_'], "");
    [
        "apikey",
        "accesstoken",
        "refreshtoken",
        "password",
        "privatekey",
        "clientsecret",
        "secret",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}
fn content_quarantine_reasons(value: &Value) -> Vec<String> {
    let mut reasons = Vec::new();
    if value.get("authoritative") == Some(&Value::Bool(true)) {
        reasons.push("AI content cannot claim authoritative enterprise status".into());
    }
    if value
        .as_object()
        .is_some_and(|map| map.keys().any(|key| secret_name(key)))
    {
        reasons.push("AI content contains prohibited secret-like fields".into());
    }
    reasons
}
fn map_unique(error: sqlx::Error, code: &'static str, message: &'static str) -> AppError {
    if error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23505") {
        AppError::conflict(code, message)
    } else {
        error.into()
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn public_batch(r: &sqlx::postgres::PgRow) -> Value {
    json!({"id":r.get::<Uuid,_>("id"),"workspaceId":r.get::<Uuid,_>("workspace_id"),"traceId":r.get::<Uuid,_>("trace_id"),"source":r.get::<String,_>("source"),"contractVersion":r.get::<String,_>("contract_version"),"schemaVersion":r.get::<String,_>("schema_version"),"cursor":{"start":r.get::<String,_>("cursor_start"),"end":r.get::<String,_>("cursor_end")},"status":r.get::<String,_>("status"),"manifest":r.get::<Value,_>("manifest"),"manifestHash":r.get::<String,_>("manifest_hash"),"recordCount":r.get::<i32,_>("record_count"),"classifications":r.get::<Vec<String>,_>("classifications"),"sealedAt":r.get::<DateTime<Utc>,_>("sealed_at")})
}
fn public_source(r: &sqlx::postgres::PgRow) -> Value {
    json!({"source":r.get::<String,_>("source"),"status":r.get::<String,_>("status"),"reason":r.get::<String,_>("reason"),"version":r.get::<i64,_>("version"),"updated_by":r.get::<String,_>("updated_by"),"updated_at":r.get::<DateTime<Utc>,_>("updated_at"),"contract_count":r.get::<i32,_>("contract_count"),"latest_contract_at":r.try_get::<Option<DateTime<Utc>>,_>("latest_contract_at").unwrap_or(None)})
}
fn public_source_control(r: &sqlx::postgres::PgRow) -> Value {
    json!({"workspace_id":r.get::<Uuid,_>("workspace_id"),"source":r.get::<String,_>("source"),"status":r.get::<String,_>("status"),"reason":r.get::<String,_>("reason"),"version":r.get::<i64,_>("version"),"updated_by":r.get::<String,_>("updated_by"),"updated_at":r.get::<DateTime<Utc>,_>("updated_at")})
}
fn public_contract(r: &sqlx::postgres::PgRow) -> Value {
    json!({"id":r.get::<Uuid,_>("id"),"workspace_id":r.get::<Uuid,_>("workspace_id"),"source":r.get::<String,_>("source"),"version":r.get::<String,_>("version"),"rules":r.get::<Value,_>("rules"),"freshness_slo_seconds":r.get::<i32,_>("freshness_slo_seconds"),"retention_days":r.get::<i32,_>("retention_days"),"created_by":r.get::<String,_>("created_by"),"created_at":r.get::<DateTime<Utc>,_>("created_at")})
}
fn public_projection(r: &sqlx::postgres::PgRow) -> Value {
    json!({"id":r.get::<Uuid,_>("id"),"workspaceId":r.get::<Uuid,_>("workspace_id"),"backupBatchId":r.get::<Uuid,_>("backup_batch_id"),"traceId":r.get::<Uuid,_>("trace_id"),"missionId":r.get::<String,_>("mission_id"),"runnerId":r.get::<String,_>("runner_id"),"contractVersion":r.get::<String,_>("contract_version"),"version":r.get::<i32,_>("version"),"status":r.get::<String,_>("status"),"payload":r.get::<Value,_>("payload"),"projectionHash":r.get::<String,_>("projection_hash"),"createdAt":r.get::<DateTime<Utc>,_>("created_at")})
}
fn public_ai_result(r: &sqlx::postgres::PgRow) -> Value {
    json!({"id":r.get::<Uuid,_>("id"),"workspaceId":r.get::<Uuid,_>("workspace_id"),"backupBatchId":r.get::<Uuid,_>("backup_batch_id"),"projectionId":r.get::<Uuid,_>("projection_id"),"traceId":r.get::<Uuid,_>("trace_id"),"experimentId":r.get::<String,_>("experiment_id"),"kind":r.get::<String,_>("kind"),"status":r.get::<String,_>("status"),"evidenceRefs":r.get::<Vec<String>,_>("evidence_refs"),"content":r.get::<Value,_>("content"),"contentHash":r.get::<String,_>("content_hash"),"quarantineReasons":r.get::<Vec<String>,_>("quarantine_reasons"),"createdAt":r.get::<DateTime<Utc>,_>("created_at")})
}
fn public_mission(r: &sqlx::postgres::PgRow) -> Value {
    json!({"id":r.get::<Uuid,_>("id"),"workspaceId":r.get::<Uuid,_>("workspace_id"),"projectionId":r.get::<Uuid,_>("projection_id"),"backupBatchId":r.get::<Uuid,_>("backup_batch_id"),"traceId":r.get::<Uuid,_>("trace_id"),"name":r.get::<String,_>("name"),"objective":r.get::<String,_>("objective"),"successMetric":r.get::<String,_>("success_metric"),"guardMetric":r.get::<String,_>("guard_metric"),"constraints":r.get::<Value,_>("constraints"),"budget":r.get::<Value,_>("budget"),"toolScope":r.get::<Vec<String>,_>("tool_scope"),"ownerId":r.get::<String,_>("owner_id"),"runnerId":r.get::<String,_>("runner_id"),"status":r.get::<String,_>("status"),"statusReason":r.get::<Option<String>,_>("status_reason"),"createdAt":r.get::<DateTime<Utc>,_>("created_at"),"updatedAt":r.get::<DateTime<Utc>,_>("updated_at")})
}
fn public_experiment(r: &sqlx::postgres::PgRow, branches: Vec<Value>) -> Value {
    json!({"id":r.get::<Uuid,_>("id"),"missionId":r.get::<Uuid,_>("mission_id"),"projectionId":r.get::<Uuid,_>("projection_id"),"traceId":r.get::<Uuid,_>("trace_id"),"attempt":r.get::<i32,_>("attempt"),"status":r.get::<String,_>("status"),"requestedBranches":r.get::<i32,_>("requested_branches"),"agentVersion":r.get::<String,_>("agent_version"),"toolVersion":r.get::<String,_>("tool_version"),"inputHash":r.get::<String,_>("input_hash"),"summary":r.get::<Value,_>("summary"),"startedAt":r.get::<DateTime<Utc>,_>("started_at"),"completedAt":r.get::<Option<DateTime<Utc>>,_>("completed_at"),"branches":branches})
}
fn public_branch(r: &sqlx::postgres::PgRow) -> Value {
    json!({"id":r.get::<Uuid,_>("id"),"experimentId":r.get::<Uuid,_>("experiment_id"),"name":r.get::<String,_>("name"),"strategy":r.get::<String,_>("strategy"),"ordinal":r.get::<i32,_>("ordinal"),"status":r.get::<String,_>("status"),"confidence":r.get::<f64,_>("confidence"),"assumptions":r.get::<Value,_>("assumptions"),"blindSpots":r.get::<Value,_>("blind_spots"),"metrics":r.get::<Value,_>("metrics"),"delta":r.get::<Value,_>("metric_delta"),"steps":r.get::<Value,_>("replay_steps"),"stateHash":r.get::<String,_>("state_hash"),"reproducible":r.get::<bool,_>("reproducible"),"createdAt":r.get::<DateTime<Utc>,_>("created_at")})
}
