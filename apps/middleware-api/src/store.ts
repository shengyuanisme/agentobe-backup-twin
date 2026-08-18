import { createHmac, randomUUID } from "node:crypto";
import type pg from "pg";
import {
  canonicalJson,
  sha256,
  type CreateAIResult,
  type CreateBackupBatch,
  type CreateProjection,
  type CreateReplicationContract,
  type ChangeReplicationSourceState,
  type EnterpriseEventInput,
} from "@agentobe/contracts";
import { AppError } from "./errors.js";
import {
  assertNoSecretFields,
  findAIResultQuarantineReasons,
} from "./security/content-policy.js";
import { EncryptedSourceVault, type VaultObjectMetadata } from "./vault.js";

interface ContractRules {
  allow: string[];
  tokenize: string[];
  deny: string[];
}

interface ContractRow {
  rules: ContractRules;
}

interface BackupBatchRow {
  id: string;
  workspace_id: string;
  trace_id: string;
  source: string;
  contract_version: string;
  schema_version: string;
  cursor_start: string;
  cursor_end: string;
  status: string;
  manifest: Record<string, unknown>;
  manifest_hash: string;
  record_count: number;
  classifications: string[];
  sealed_at: Date;
  created_at: Date;
}

interface EventRow {
  id: string;
  source_event_id: string;
  sequence: string | number;
  event_type: string;
  entity_type: string;
  entity_id: string;
  occurred_at: Date;
  classification: string[];
  payload: Record<string, unknown>;
  payload_checksum: string;
}

interface ProjectionRow {
  id: string;
  workspace_id: string;
  backup_batch_id: string;
  trace_id: string;
  mission_id: string;
  runner_id: string;
  contract_version: string;
  version: number;
  status: string;
  payload: ProjectionPayload;
  projection_hash: string;
  created_at: Date;
}

interface ProjectionPayload {
  sourceBatchId: string;
  sourceManifestHash: string;
  missionId: string;
  runnerId: string;
  contractVersion: string;
  tickets: Array<Record<string, unknown> & { ticket_id?: string }>;
}

interface SourceBackupObjectRow {
  object_key: string;
  storage_driver: "file" | "spaces" | "memory";
  encryption_algorithm: "AES-256-GCM";
  key_wrap_algorithm: "AES-256-GCM";
  key_version: string;
  plaintext_hash: string;
  ciphertext_hash: string;
  size_bytes: string | number;
}

function toPublicBatch(row: BackupBatchRow) {
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    traceId: row.trace_id,
    source: row.source,
    contractVersion: row.contract_version,
    schemaVersion: row.schema_version,
    cursor: { start: row.cursor_start, end: row.cursor_end },
    status: row.status,
    manifest: row.manifest,
    manifestHash: row.manifest_hash,
    recordCount: row.record_count,
    classifications: row.classifications,
    sealedAt: row.sealed_at,
  };
}

function toPublicProjection(row: ProjectionRow) {
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    backupBatchId: row.backup_batch_id,
    traceId: row.trace_id,
    missionId: row.mission_id,
    runnerId: row.runner_id,
    contractVersion: row.contract_version,
    version: row.version,
    status: row.status,
    payload: row.payload,
    projectionHash: row.projection_hash,
    createdAt: row.created_at,
  };
}

function manifestEvent(event: EnterpriseEventInput, checksum: string) {
  return {
    sourceEventId: event.sourceEventId,
    sequence: event.sequence,
    eventType: event.eventType,
    entityType: event.entityType,
    entityId: event.entityId,
    occurredAt: event.occurredAt,
    classification: [...event.classification].sort(),
    checksum,
  };
}

function manifestEventFromRow(event: EventRow) {
  return {
    sourceEventId: event.source_event_id,
    sequence: Number(event.sequence),
    eventType: event.event_type,
    entityType: event.entity_type,
    entityId: event.entity_id,
    occurredAt: event.occurred_at.toISOString(),
    classification: [...event.classification].sort(),
    checksum: event.payload_checksum,
  };
}

export class MiddlewareStore {
  constructor(
    private readonly pool: pg.Pool,
    private readonly projectionTokenKey: string,
    private readonly sourceVault: EncryptedSourceVault,
  ) {}

  private async getContract(
    client: pg.Pool | pg.PoolClient,
    workspaceId: string,
    source: string,
    version: string,
  ): Promise<ContractRules> {
    const result = await client.query<ContractRow>(
      `SELECT rules
       FROM replication_contracts
       WHERE workspace_id = $1 AND source = $2 AND version = $3 AND active = true`,
      [workspaceId, source, version],
    );
    const contract = result.rows[0];
    if (!contract) {
      throw new AppError(404, "REPLICATION_CONTRACT_NOT_FOUND", "Active replication contract not found.");
    }
    return contract.rules;
  }

  private validateEvents(events: EnterpriseEventInput[], rules: ContractRules): string[] {
    const ordered = [...events].sort((left, right) => left.sequence - right.sequence);
    for (let index = 1; index < ordered.length; index += 1) {
      if (ordered[index]!.sequence !== ordered[index - 1]!.sequence + 1) {
        throw new AppError(422, "EVENT_SEQUENCE_GAP", "Event sequence must be contiguous.", {
          previous: ordered[index - 1]!.sequence,
          current: ordered[index]!.sequence,
        });
      }
    }

    const classifications = new Set<string>();
    for (const event of ordered) {
      event.classification.forEach((entry) => classifications.add(entry));
      if (event.classification.includes("D4")) {
        throw new AppError(422, "D4_SECRET_REJECTED", "D4-classified events are prohibited.");
      }
      assertNoSecretFields(event.payload);

      const keys = Object.keys(event.payload);
      const denied = keys.filter((key) => rules.deny.includes(key));
      const outsideContract = keys.filter((key) => !rules.allow.includes(key));
      if (denied.length > 0 || outsideContract.length > 0) {
        throw new AppError(
          422,
          "REPLICATION_CONTRACT_VIOLATION",
          "Event contains fields outside the active replication contract.",
          { denied, outsideContract },
        );
      }

      const computed = sha256(event.payload);
      if (event.checksum && event.checksum !== computed) {
        throw new AppError(422, "CHECKSUM_MISMATCH", "Event checksum does not match its canonical payload.", {
          sourceEventId: event.sourceEventId,
          expected: event.checksum,
          actual: computed,
        });
      }
    }
    return [...classifications].sort();
  }

  async findBatchByCursor(
    workspaceId: string,
    source: string,
    cursorEnd: string,
  ) {
    const result = await this.pool.query<BackupBatchRow>(
      `SELECT * FROM backup_batches
       WHERE workspace_id = $1 AND source = $2 AND cursor_end = $3`,
      [workspaceId, source, cursorEnd],
    );
    return result.rows[0] ? toPublicBatch(result.rows[0]) : undefined;
  }

  async createBackupBatch(workspaceId: string, input: CreateBackupBatch, actorId: string) {
    const batchId = randomUUID();
    let vaultMetadata: VaultObjectMetadata | undefined;
    let committed = false;
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const workspace = await client.query(
        "SELECT id, status FROM workspaces WHERE id = $1 FOR SHARE",
        [workspaceId],
      );
      if (!workspace.rows[0]) {
        throw new AppError(404, "WORKSPACE_NOT_FOUND", "Workspace not found.");
      }
      if (workspace.rows[0].status !== "active") {
        throw new AppError(409, "WORKSPACE_STOPPED", "Workspace ingestion is stopped.");
      }

      const sourceControl = await client.query<{ status: string }>(
        `SELECT status FROM replication_source_controls
         WHERE workspace_id = $1 AND source = $2 FOR SHARE`,
        [workspaceId, input.source],
      );
      if (sourceControl.rows[0]?.status === "paused") {
        throw new AppError(409, "REPLICATION_SOURCE_PAUSED", "Replication source is paused.");
      }

      const rules = await this.getContract(
        client,
        workspaceId,
        input.source,
        input.contractVersion,
      );
      const classifications = this.validateEvents(input.events, rules);
      const traceId = input.traceId ?? randomUUID();
      const sealedAt = new Date();
      const eventEntries = [...input.events]
        .sort((left, right) => left.sequence - right.sequence)
        .map((event) => manifestEvent(event, sha256(event.payload)));
      const manifest = {
        format: "agentobe.backup-manifest.v1",
        workspaceId,
        source: input.source,
        contractVersion: input.contractVersion,
        schemaVersion: input.schemaVersion,
        cursor: input.cursor,
        recordCount: input.events.length,
        classifications,
        events: eventEntries,
      };
      const manifestHash = sha256(manifest);
      vaultMetadata = await this.sourceVault.put(workspaceId, batchId, {
        format: "agentobe.source-backup.v1",
        workspaceId,
        batchId,
        source: input.source,
        contractVersion: input.contractVersion,
        schemaVersion: input.schemaVersion,
        cursor: input.cursor,
        events: input.events,
      });

      const inserted = await client.query<BackupBatchRow>(
        `INSERT INTO backup_batches (
           id, workspace_id, trace_id, source, contract_version, schema_version,
           cursor_start, cursor_end, status, manifest, manifest_hash, record_count,
           classifications, sealed_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'sealed',$9,$10,$11,$12,$13)
         RETURNING *`,
        [
          batchId,
          workspaceId,
          traceId,
          input.source,
          input.contractVersion,
          input.schemaVersion,
          input.cursor.start,
          input.cursor.end,
          manifest,
          manifestHash,
          input.events.length,
          classifications,
          sealedAt,
        ],
      );

      for (const event of input.events) {
        await client.query(
          `INSERT INTO enterprise_events (
             id, workspace_id, backup_batch_id, source_event_id, sequence, event_type,
             entity_type, entity_id, occurred_at, classification, payload, payload_checksum
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
          [
            randomUUID(), workspaceId, batchId, event.sourceEventId, event.sequence,
            event.eventType, event.entityType, event.entityId, event.occurredAt,
            event.classification, event.payload, sha256(event.payload),
          ],
        );
      }

      await client.query(
        `INSERT INTO source_backup_objects (
           id, workspace_id, backup_batch_id, object_key, storage_driver,
           encryption_algorithm, key_wrap_algorithm, key_version, plaintext_hash,
           ciphertext_hash, size_bytes
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [
          randomUUID(), workspaceId, batchId, vaultMetadata.objectKey,
          vaultMetadata.storageDriver, vaultMetadata.encryptionAlgorithm,
          vaultMetadata.keyWrapAlgorithm, vaultMetadata.keyVersion,
          vaultMetadata.plaintextHash, vaultMetadata.ciphertextHash,
          vaultMetadata.sizeBytes,
        ],
      );

      await this.appendEvent(client, {
        workspaceId,
        traceId,
        plane: "enterprise",
        actorId,
        eventType: "backup.batch.sealed",
        objectType: "backup_batch",
        objectId: batchId,
        classification: classifications,
        metadata: {
          manifestHash,
          recordCount: input.events.length,
          vaultCiphertextHash: vaultMetadata.ciphertextHash,
          vaultKeyVersion: vaultMetadata.keyVersion,
        },
      });
      await client.query("COMMIT");
      committed = true;
      return toPublicBatch(inserted.rows[0]!);
    } catch (error) {
      await client.query("ROLLBACK");
      if (vaultMetadata && !committed) {
        await this.sourceVault.delete(vaultMetadata.objectKey).catch(() => undefined);
      }
      if ((error as { code?: string }).code === "23505") {
        throw new AppError(409, "DUPLICATE_BACKUP_BATCH", "This source cursor or event was already ingested.");
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async listReplicationSources(workspaceId: string) {
    const result = await this.pool.query(
      `SELECT c.workspace_id, c.source, c.status, c.reason, c.version,
              c.updated_by, c.updated_at,
              COUNT(rc.id)::int AS contract_count,
              MAX(rc.created_at) AS latest_contract_at
       FROM replication_source_controls c
       LEFT JOIN replication_contracts rc
         ON rc.workspace_id = c.workspace_id AND rc.source = c.source
       WHERE c.workspace_id = $1
       GROUP BY c.workspace_id, c.source, c.status, c.reason, c.version,
                c.updated_by, c.updated_at
       ORDER BY c.source`,
      [workspaceId],
    );
    return result.rows;
  }

  async listReplicationContracts(workspaceId: string, source?: string) {
    const result = await this.pool.query(
      `SELECT id, workspace_id, source, version, rules, freshness_slo_seconds,
              retention_days, created_by, created_at
       FROM replication_contracts
       WHERE workspace_id = $1 AND ($2::text IS NULL OR source = $2)
       ORDER BY source, created_at DESC`,
      [workspaceId, source ?? null],
    );
    return result.rows;
  }

  async createReplicationContract(
    workspaceId: string,
    input: CreateReplicationContract,
    actorId: string,
  ) {
    validateContractRules(input.rules);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const workspace = await client.query("SELECT id FROM workspaces WHERE id = $1", [workspaceId]);
      if (!workspace.rows[0]) throw new AppError(404, "WORKSPACE_NOT_FOUND", "Workspace not found.");
      const id = randomUUID();
      const inserted = await client.query(
        `INSERT INTO replication_contracts (
           id, workspace_id, source, version, rules, freshness_slo_seconds,
           retention_days, active, created_by
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,true,$8)
         RETURNING id, workspace_id, source, version, rules, freshness_slo_seconds,
                   retention_days, created_by, created_at`,
        [
          id, workspaceId, input.source, input.version, input.rules,
          input.freshnessSloSeconds, input.retentionDays, actorId,
        ],
      );
      await client.query(
        `INSERT INTO replication_source_controls (
           workspace_id, source, status, reason, updated_by
         ) VALUES ($1,$2,'active','Source activated with first contract',$3)
         ON CONFLICT (workspace_id, source) DO NOTHING`,
        [workspaceId, input.source, actorId],
      );
      const traceId = randomUUID();
      await this.appendEvent(client, {
        workspaceId,
        traceId,
        plane: "control",
        actorId,
        eventType: "replication.contract.created",
        objectType: "replication_contract",
        objectId: id,
        classification: ["D1"],
        metadata: { source: input.source, version: input.version },
      });
      await client.query("COMMIT");
      return inserted.rows[0];
    } catch (error) {
      await client.query("ROLLBACK");
      if ((error as { code?: string }).code === "23505") {
        throw new AppError(409, "CONTRACT_VERSION_EXISTS", "Replication contract version already exists.");
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async changeReplicationSourceState(
    workspaceId: string,
    source: string,
    input: ChangeReplicationSourceState,
    actorId: string,
  ) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const updated = await client.query(
        `UPDATE replication_source_controls
         SET status = $3, reason = $4, version = version + 1,
             updated_by = $5, updated_at = now()
         WHERE workspace_id = $1 AND source = $2
         RETURNING workspace_id, source, status, reason, version, updated_by, updated_at`,
        [workspaceId, source, input.status, input.reason, actorId],
      );
      if (!updated.rows[0]) {
        throw new AppError(404, "REPLICATION_SOURCE_NOT_FOUND", "Replication source not found.");
      }
      await this.appendEvent(client, {
        workspaceId,
        traceId: randomUUID(),
        plane: "control",
        actorId,
        eventType: input.status === "paused" ? "replication.source.paused" : "replication.source.resumed",
        objectType: "replication_source",
        objectId: source,
        classification: ["D1"],
        metadata: { reason: input.reason, version: updated.rows[0].version },
      });
      await client.query("COMMIT");
      return updated.rows[0];
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async listBackupBatches(workspaceId: string) {
    const result = await this.pool.query<BackupBatchRow>(
      "SELECT * FROM backup_batches WHERE workspace_id = $1 ORDER BY created_at DESC",
      [workspaceId],
    );
    return result.rows.map(toPublicBatch);
  }

  async getBackupBatch(workspaceId: string, batchId: string) {
    const result = await this.pool.query<BackupBatchRow>(
      "SELECT * FROM backup_batches WHERE id = $1 AND workspace_id = $2",
      [batchId, workspaceId],
    );
    const row = result.rows[0];
    if (!row) throw new AppError(404, "BACKUP_BATCH_NOT_FOUND", "Backup batch not found.");
    return toPublicBatch(row);
  }

  async createProjection(
    workspaceId: string,
    batchId: string,
    input: CreateProjection,
    actorId: string,
  ) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const batchResult = await client.query<BackupBatchRow>(
        "SELECT * FROM backup_batches WHERE id = $1 AND workspace_id = $2 FOR SHARE",
        [batchId, workspaceId],
      );
      const batch = batchResult.rows[0];
      if (!batch) throw new AppError(404, "BACKUP_BATCH_NOT_FOUND", "Backup batch not found.");
      if (batch.status !== "sealed") {
        throw new AppError(409, "BACKUP_BATCH_NOT_HEALTHY", "Only a sealed backup batch can be projected.");
      }
      const rules = await this.getContract(
        client,
        workspaceId,
        batch.source,
        input.contractVersion,
      );
      const eventResult = await client.query<EventRow>(
        "SELECT * FROM enterprise_events WHERE backup_batch_id = $1 ORDER BY sequence",
        [batchId],
      );
      const tickets = eventResult.rows.map((event) => {
        if (event.classification.includes("D3") || event.classification.includes("D4")) {
          throw new AppError(422, "PROJECTION_CLASSIFICATION_BLOCKED", "D3/D4 records cannot enter the default AI projection.");
        }
        const projected = Object.fromEntries(
          Object.entries(event.payload)
            .filter(([key]) => rules.allow.includes(key) && !rules.deny.includes(key))
            .map(([key, value]) => [
              key,
              rules.tokenize.includes(key) ? this.tokenize(workspaceId, String(value)) : value,
            ]),
        );
        return {
          ...projected,
          _lineage: {
            sourceEventId: event.source_event_id,
            sourceChecksum: event.payload_checksum,
            backupBatchId: batchId,
          },
        };
      });
      const payload: ProjectionPayload = {
        sourceBatchId: batchId,
        sourceManifestHash: batch.manifest_hash,
        missionId: input.missionId,
        runnerId: input.runnerId,
        contractVersion: input.contractVersion,
        tickets,
      };
      const projectionHash = sha256(payload);
      const projectionId = randomUUID();
      const versionResult = await client.query<{ next_version: number }>(
        `SELECT COALESCE(MAX(version), 0)::int + 1 AS next_version
         FROM ai_projections
         WHERE backup_batch_id = $1 AND mission_id = $2 AND runner_id = $3`,
        [batchId, input.missionId, input.runnerId],
      );
      const version = versionResult.rows[0]!.next_version;
      const inserted = await client.query<ProjectionRow>(
        `INSERT INTO ai_projections (
           id, workspace_id, backup_batch_id, trace_id, mission_id, runner_id,
           contract_version, version, status, payload, projection_hash
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'sealed',$9,$10)
         RETURNING *`,
        [
          projectionId, workspaceId, batchId, batch.trace_id, input.missionId,
          input.runnerId, input.contractVersion, version, payload, projectionHash,
        ],
      );
      await this.appendEvent(client, {
        workspaceId,
        traceId: batch.trace_id,
        plane: "shadow",
        actorId,
        eventType: "ai.projection.sealed",
        objectType: "ai_projection",
        objectId: projectionId,
        classification: ["D1", "D2"],
        metadata: { backupBatchId: batchId, projectionHash, version },
      });
      await client.query("COMMIT");
      return toPublicProjection(inserted.rows[0]!);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async getProjection(workspaceId: string, projectionId: string) {
    const result = await this.pool.query<ProjectionRow>(
      "SELECT * FROM ai_projections WHERE id = $1 AND workspace_id = $2",
      [projectionId, workspaceId],
    );
    const row = result.rows[0];
    if (!row) throw new AppError(404, "PROJECTION_NOT_FOUND", "AI projection not found.");
    return toPublicProjection(row);
  }

  async createAIResult(workspaceId: string, input: CreateAIResult, actorId: string) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const projectionResult = await client.query<ProjectionRow>(
        "SELECT * FROM ai_projections WHERE id = $1 AND workspace_id = $2 FOR SHARE",
        [input.projectionId, workspaceId],
      );
      const projection = projectionResult.rows[0];
      if (!projection) throw new AppError(404, "PROJECTION_NOT_FOUND", "AI projection not found.");
      if (projection.runner_id !== actorId) {
        throw new AppError(403, "RUNNER_IDENTITY_MISMATCH", "Runner identity cannot write to this projection.");
      }
      if (Buffer.byteLength(canonicalJson(input.content), "utf8") > 65_536) {
        throw new AppError(413, "AI_RESULT_TOO_LARGE", "Inline AI result exceeds 64 KiB.");
      }

      const validEvidence = new Set(
        projection.payload.tickets
          .map((ticket) => ticket.ticket_id)
          .filter((ticketId): ticketId is string => typeof ticketId === "string")
          .map((ticketId) => `ticket:${ticketId}`),
      );
      const quarantineReasons = [
        ...findAIResultQuarantineReasons(input.content),
        ...input.evidenceRefs
          .filter((reference) => !validEvidence.has(reference))
          .map((reference) => `unknown evidence reference: ${reference}`),
      ];
      const status = quarantineReasons.length > 0
        ? "quarantined"
        : input.kind === "action_proposal"
          ? "pending_compilation"
          : "recorded";
      const resultId = randomUUID();
      const contentHash = sha256(input.content);
      const inserted = await client.query(
        `INSERT INTO ai_results (
           id, workspace_id, backup_batch_id, projection_id, trace_id, experiment_id,
           agent_version, tool_version, kind, status, evidence_refs, content,
           content_hash, quarantine_reasons
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         RETURNING *`,
        [
          resultId, workspaceId, projection.backup_batch_id, projection.id,
          projection.trace_id, input.experimentId, input.agentVersion, input.toolVersion,
          input.kind, status, input.evidenceRefs, input.content, contentHash,
          quarantineReasons,
        ],
      );
      await this.appendEvent(client, {
        workspaceId,
        traceId: projection.trace_id,
        plane: "shadow",
        actorId,
        eventType: status === "quarantined" ? "ai.result.quarantined" : "ai.result.recorded",
        objectType: "ai_result",
        objectId: resultId,
        classification: ["D1"],
        metadata: { projectionId: projection.id, kind: input.kind, status, contentHash },
      });
      await client.query("COMMIT");
      const row = inserted.rows[0];
      return {
        id: row.id,
        workspaceId: row.workspace_id,
        backupBatchId: row.backup_batch_id,
        projectionId: row.projection_id,
        traceId: row.trace_id,
        experimentId: row.experiment_id,
        kind: row.kind,
        status: row.status,
        evidenceRefs: row.evidence_refs,
        content: row.content,
        contentHash: row.content_hash,
        quarantineReasons: row.quarantine_reasons,
        createdAt: row.created_at,
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async verifyRestore(workspaceId: string, batchId: string) {
    const batchResult = await this.pool.query<BackupBatchRow>(
      "SELECT * FROM backup_batches WHERE id = $1 AND workspace_id = $2",
      [batchId, workspaceId],
    );
    const batch = batchResult.rows[0];
    if (!batch) throw new AppError(404, "BACKUP_BATCH_NOT_FOUND", "Backup batch not found.");
    const eventResult = await this.pool.query<EventRow>(
      "SELECT * FROM enterprise_events WHERE backup_batch_id = $1 ORDER BY sequence",
      [batchId],
    );
    const checksumFailures = eventResult.rows
      .filter((event) => sha256(event.payload) !== event.payload_checksum)
      .map((event) => event.source_event_id);
    const restoredManifest = {
      format: "agentobe.backup-manifest.v1",
      workspaceId,
      source: batch.source,
      contractVersion: batch.contract_version,
      schemaVersion: batch.schema_version,
      cursor: { start: batch.cursor_start, end: batch.cursor_end },
      recordCount: eventResult.rows.length,
      classifications: [...batch.classifications].sort(),
      events: eventResult.rows.map(manifestEventFromRow),
    };
    const restoredManifestHash = sha256(restoredManifest);
    const tickets = Object.fromEntries(
      eventResult.rows.map((event) => [event.entity_id, event.payload]),
    );
    return {
      batchId,
      status:
        checksumFailures.length === 0 && restoredManifestHash === batch.manifest_hash
          ? "healthy"
          : "failed",
      recordCount: eventResult.rows.length,
      checksumFailures,
      expectedManifestHash: batch.manifest_hash,
      restoredManifestHash,
      restoredStateHash: sha256(tickets),
    };
  }

  async verifyVaultObject(workspaceId: string, batchId: string) {
    const result = await this.pool.query<SourceBackupObjectRow>(
      `SELECT object_key, storage_driver, encryption_algorithm, key_wrap_algorithm,
              key_version, plaintext_hash, ciphertext_hash, size_bytes
       FROM source_backup_objects
       WHERE workspace_id = $1 AND backup_batch_id = $2`,
      [workspaceId, batchId],
    );
    const row = result.rows[0];
    if (!row) throw new AppError(404, "VAULT_OBJECT_NOT_FOUND", "Encrypted source backup object not found.");
    const metadata: VaultObjectMetadata = {
      objectKey: row.object_key,
      storageDriver: row.storage_driver,
      encryptionAlgorithm: row.encryption_algorithm,
      keyWrapAlgorithm: row.key_wrap_algorithm,
      keyVersion: row.key_version,
      plaintextHash: row.plaintext_hash,
      ciphertextHash: row.ciphertext_hash,
      sizeBytes: Number(row.size_bytes),
    };
    return { batchId, object: metadata, verification: await this.sourceVault.verify(metadata) };
  }

  async getTrace(workspaceId: string, traceId: string) {
    const result = await this.pool.query(
      `SELECT id, trace_id, plane, actor_id, event_type, object_type, object_id,
              classification, metadata, created_at
       FROM audit_events
       WHERE workspace_id = $1 AND trace_id = $2
       ORDER BY created_at, id`,
      [workspaceId, traceId],
    );
    return { workspaceId, traceId, events: result.rows };
  }

  private tokenize(workspaceId: string, value: string): string {
    return `tok_${createHmac("sha256", this.projectionTokenKey)
      .update(`${workspaceId}:${value}`)
      .digest("hex")
      .slice(0, 24)}`;
  }

  private async appendEvent(
    client: pg.PoolClient,
    event: {
      workspaceId: string;
      traceId: string;
      plane: "enterprise" | "shadow" | "control";
      actorId: string;
      eventType: string;
      objectType: string;
      objectId: string;
      classification: string[];
      metadata: Record<string, unknown>;
    },
  ): Promise<void> {
    const eventId = randomUUID();
    await client.query(
      `INSERT INTO audit_events (
         id, workspace_id, trace_id, plane, actor_id, event_type, object_type,
         object_id, classification, metadata
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        eventId, event.workspaceId, event.traceId, event.plane, event.actorId,
        event.eventType, event.objectType, event.objectId, event.classification,
        event.metadata,
      ],
    );
    await client.query(
      `INSERT INTO outbox_events (id, workspace_id, trace_id, topic, payload)
       VALUES ($1,$2,$3,$4,$5)`,
      [
        randomUUID(), event.workspaceId, event.traceId, event.eventType,
        { eventId, objectType: event.objectType, objectId: event.objectId, ...event.metadata },
      ],
    );
  }
}

function validateContractRules(rules: CreateReplicationContract["rules"]): void {
  const overlap = rules.allow.filter((field) => rules.deny.includes(field));
  const invalidTokenize = rules.tokenize.filter((field) => !rules.allow.includes(field));
  const secretPattern = /(api_?key|access_?token|refresh_?token|password|private_?key|client_?secret|secret)/i;
  const secretAllowed = rules.allow.filter((field) => secretPattern.test(field));
  if (overlap.length || invalidTokenize.length || secretAllowed.length) {
    throw new AppError(422, "INVALID_REPLICATION_CONTRACT", "Replication field rules are inconsistent or unsafe.", {
      overlap,
      invalidTokenize,
      secretAllowed,
    });
  }
}
