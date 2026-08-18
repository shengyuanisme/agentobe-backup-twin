import type { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEMO_WORKSPACE_ID } from "@agentobe/contracts";
import { loadConfig } from "./config.js";
import { migrate } from "./db/migrate.js";
import { createPool } from "./db/pool.js";
import { buildServer } from "./server.js";
import { EncryptedSourceVault, MemoryBlobStore } from "./vault.js";
import { drainOutboxOnce, type OutboxMessage } from "./outbox-worker.js";
import { StaticAccessTokenVerifier } from "./auth.js";

const identityHeaders = { authorization: "Bearer admin-token" };
const runnerHeaders = { authorization: "Bearer runner-token" };
const viewerHeaders = { authorization: "Bearer viewer-token" };
const outsiderHeaders = { authorization: "Bearer outsider-token" };
const TEST_ISSUER = "https://identity.test.example";

describe("backup and simulation middleware Slice 1", () => {
  let pool: Pool;
  let app: Awaited<ReturnType<typeof buildServer>>;

  beforeAll(async () => {
    const config = loadConfig();
    await migrate(config.databaseUrl);
    pool = createPool(config.databaseUrl);
    await pool.query(
      "TRUNCATE outbox_events, audit_events, ai_results, ai_projections, source_backup_objects, enterprise_events, backup_batches RESTART IDENTITY CASCADE",
    );
    await pool.query(
      "UPDATE replication_source_controls SET status = 'active', reason = 'test reset'",
    );
    await pool.query(
      `INSERT INTO oidc_principals (issuer, subject, email, display_name)
       VALUES
         ($1, 'replicator-demo', 'admin@example.test', 'Test Admin'),
         ($1, 'shadow-runner-demo', 'runner@example.test', 'Test Runner'),
         ($1, 'viewer-demo', 'viewer@example.test', 'Test Viewer')
       ON CONFLICT (issuer, subject) DO UPDATE SET email = EXCLUDED.email`,
      [TEST_ISSUER],
    );
    await pool.query(
      `INSERT INTO organizations (id, slug, name)
       VALUES ('00000000-0000-4000-8000-000000000020', 'partner-test', 'Partner Test')
       ON CONFLICT (id) DO NOTHING`,
    );
    await pool.query(
      `INSERT INTO workspaces (id, organization_id, name, risk_profile)
       VALUES (
         '00000000-0000-4000-8000-000000000002',
         '00000000-0000-4000-8000-000000000020',
         'Partner Workspace', 'test'
       ) ON CONFLICT (id) DO NOTHING`,
    );
    await pool.query(
      `INSERT INTO oidc_principals (issuer, subject, email)
       VALUES ($1, 'partner-outsider', 'outsider@example.test')
       ON CONFLICT (issuer, subject) DO NOTHING`,
      [TEST_ISSUER],
    );
    await pool.query(
      `INSERT INTO organization_memberships (
         organization_id, principal_id, roles, status, created_by
       )
       SELECT '00000000-0000-4000-8000-000000000020', id,
              ARRAY['viewer']::text[], 'active', 'test'
       FROM oidc_principals WHERE issuer = $1 AND subject = 'partner-outsider'
       ON CONFLICT (organization_id, principal_id) DO UPDATE
       SET roles = EXCLUDED.roles, status = 'active'`,
      [TEST_ISSUER],
    );
    await pool.query(
      `DELETE FROM organization_memberships m
       USING oidc_principals p
       WHERE m.principal_id = p.id
         AND m.organization_id = '00000000-0000-4000-8000-000000000010'
         AND p.issuer = $1 AND p.subject = 'partner-outsider'`,
      [TEST_ISSUER],
    );
    await pool.query(
      `INSERT INTO organization_memberships (
         organization_id, principal_id, roles, status, created_by
       )
       SELECT '00000000-0000-4000-8000-000000000010', id,
              CASE subject
                WHEN 'replicator-demo' THEN ARRAY['owner']::text[]
                WHEN 'shadow-runner-demo' THEN ARRAY['runner']::text[]
                ELSE ARRAY['viewer']::text[]
              END,
              'active', 'test'
       FROM oidc_principals
       WHERE issuer = $1
         AND subject IN ('replicator-demo', 'shadow-runner-demo', 'viewer-demo')
       ON CONFLICT (organization_id, principal_id) DO UPDATE
       SET roles = EXCLUDED.roles, status = 'active'`,
      [TEST_ISSUER],
    );
    app = await buildServer({
      pool,
      projectionTokenKey: "test-projection-key",
      sourceVault: new EncryptedSourceVault(
        new MemoryBlobStore(),
        "YWdlbnRvYmUtZGVtby12YXVsdC1rZXktMDAwMDAwMDA=",
        "test-v1",
      ),
      tokenVerifier: new StaticAccessTokenVerifier({
        "admin-token": { issuer: TEST_ISSUER, subject: "replicator-demo" },
        "runner-token": { issuer: TEST_ISSUER, subject: "shadow-runner-demo" },
        "viewer-token": { issuer: TEST_ISSUER, subject: "viewer-demo" },
        "outsider-token": { issuer: TEST_ISSUER, subject: "partner-outsider" },
      }),
      logLevel: "silent",
    });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
    await pool.end();
  });

  it("seals a deterministic synthetic backup and verifies restoration", async () => {
    const seeded = await app.inject({
      method: "POST",
      url: "/v1/demo/seed",
      headers: identityHeaders,
    });
    expect(seeded.statusCode).toBe(201);
    const body = seeded.json();
    expect(body.batch.status).toBe("sealed");
    expect(body.batch.recordCount).toBe(3);
    expect(body.batch.manifestHash).toMatch(/^[a-f0-9]{64}$/);

    const verified = await app.inject({
      method: "GET",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/backup-batches/${body.batch.id}/restore-verification`,
      headers: identityHeaders,
    });
    expect(verified.statusCode).toBe(200);
    expect(verified.json().status).toBe("healthy");
    expect(verified.json().expectedManifestHash).toBe(verified.json().restoredManifestHash);
    expect(verified.json()).not.toHaveProperty("tickets");

    const vault = await app.inject({
      method: "GET",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/backup-batches/${body.batch.id}/vault-verification`,
      headers: identityHeaders,
    });
    expect(vault.statusCode).toBe(200);
    expect(vault.json().verification.status).toBe("healthy");
    expect(vault.json().object.storageDriver).toBe("memory");
  });

  it("enforces OIDC authentication, role permissions, and tenant isolation", async () => {
    const unauthenticated = await app.inject({
      method: "GET",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/backup-batches`,
    });
    expect(unauthenticated.statusCode).toBe(401);
    expect(unauthenticated.json().error.code).toBe("BEARER_TOKEN_REQUIRED");

    const me = await app.inject({ method: "GET", url: "/v1/me", headers: viewerHeaders });
    expect(me.statusCode).toBe(200);
    expect(me.json().workspaces[0].roles).toEqual(["viewer"]);
    expect(me.json().workspaces[0].permissions).toEqual(["workspace:read"]);

    const readable = await app.inject({
      method: "GET",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/backup-batches`,
      headers: viewerHeaders,
    });
    expect(readable.statusCode).toBe(200);

    const viewerMutation = await app.inject({
      method: "POST",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/replication-sources/ticketing-sandbox/state`,
      headers: viewerHeaders,
      payload: { status: "paused", reason: "Viewer must not mutate" },
    });
    expect(viewerMutation.statusCode).toBe(403);
    expect(viewerMutation.json().error.code).toBe("PERMISSION_DENIED");

    const crossTenant = await app.inject({
      method: "GET",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/backup-batches`,
      headers: outsiderHeaders,
    });
    expect(crossTenant.statusCode).toBe(403);
    expect(crossTenant.json().error.code).toBe("TENANT_ACCESS_DENIED");

    const ownTenant = await app.inject({
      method: "GET",
      url: "/v1/workspaces/00000000-0000-4000-8000-000000000002/backup-batches",
      headers: outsiderHeaders,
    });
    expect(ownTenant.statusCode).toBe(200);
  });

  it("provisions and revokes tenant roles without allowing the last owner to be removed", async () => {
    const organizationId = "00000000-0000-4000-8000-000000000010";
    const created = await app.inject({
      method: "POST",
      url: `/v1/organizations/${organizationId}/memberships`,
      headers: identityHeaders,
      payload: {
        issuer: TEST_ISSUER,
        subject: "partner-auditor-demo",
        email: "auditor@partner.example",
        displayName: "Partner Auditor",
        roles: ["auditor"],
      },
    });
    expect(created.statusCode).toBe(201);

    const listed = await app.inject({
      method: "GET",
      url: `/v1/organizations/${organizationId}/memberships`,
      headers: identityHeaders,
    });
    expect(listed.statusCode).toBe(200);
    const memberships = listed.json().items as Array<{
      principal_id: string;
      subject: string;
      roles: string[];
      status: string;
    }>;
    const auditor = memberships.find((membership) => membership.subject === "partner-auditor-demo")!;
    const owner = memberships.find((membership) => membership.subject === "replicator-demo")!;
    expect(auditor.roles).toEqual(["auditor"]);

    const suspended = await app.inject({
      method: "POST",
      url: `/v1/organizations/${organizationId}/memberships/${auditor.principal_id}/state`,
      headers: identityHeaders,
      payload: { status: "suspended" },
    });
    expect(suspended.statusCode).toBe(200);
    expect(suspended.json().status).toBe("suspended");

    const lastOwner = await app.inject({
      method: "POST",
      url: `/v1/organizations/${organizationId}/memberships/${owner.principal_id}/state`,
      headers: identityHeaders,
      payload: { status: "suspended" },
    });
    expect(lastOwner.statusCode).toBe(409);
    expect(lastOwner.json().error.code).toBe("LAST_OWNER_REQUIRED");
  });

  it("versions replication contracts and enforces pause/resume", async () => {
    const partnerSource = `partner-ticketing-sandbox-${Date.now()}`;
    const created = await app.inject({
      method: "POST",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/replication-contracts`,
      headers: identityHeaders,
      payload: {
        source: partnerSource,
        version: "v1",
        rules: {
          entity: "ticket",
          mode: "snapshot_plus_events",
          allow: ["ticket_id", "state"],
          tokenize: [],
          deny: ["access_token", "password"],
          simulation_use: ["triage"],
        },
        freshnessSloSeconds: 300,
        retentionDays: 30,
      },
    });
    expect(created.statusCode).toBe(201);

    const paused = await app.inject({
      method: "POST",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/replication-sources/${partnerSource}/state`,
      headers: identityHeaders,
      payload: { status: "paused", reason: "Operator integrity review" },
    });
    expect(paused.statusCode).toBe(200);
    expect(paused.json().status).toBe("paused");

    const blocked = await app.inject({
      method: "POST",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/backup-batches`,
      headers: identityHeaders,
      payload: {
        source: partnerSource,
        contractVersion: "v1",
        schemaVersion: "ticket-v1",
        cursor: { start: "partner:1", end: "partner:1" },
        events: [{
          sourceEventId: "partner-event-1",
          sequence: 1,
          eventType: "ticket.snapshot",
          entityType: "ticket",
          entityId: "PARTNER-1",
          occurredAt: "2026-08-18T01:00:00.000Z",
          classification: ["D1"],
          payload: { ticket_id: "PARTNER-1", state: "open" },
        }],
      },
    });
    expect(blocked.statusCode).toBe(409);
    expect(blocked.json().error.code).toBe("REPLICATION_SOURCE_PAUSED");

    const resumed = await app.inject({
      method: "POST",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/replication-sources/${partnerSource}/state`,
      headers: identityHeaders,
      payload: { status: "active", reason: "Integrity review completed" },
    });
    expect(resumed.statusCode).toBe(200);
    expect(resumed.json().status).toBe("active");
    expect(Number(resumed.json().version)).toBeGreaterThan(1);
  });

  it("creates a sealed, tokenized projection without source identity leakage", async () => {
    const seeded = await app.inject({
      method: "POST",
      url: "/v1/demo/seed",
      headers: identityHeaders,
    });
    const batchId = seeded.json().batch.id;
    const projected = await app.inject({
      method: "POST",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/backup-batches/${batchId}/projections`,
      headers: identityHeaders,
      payload: {
        missionId: "sla-risk-demo",
        runnerId: "shadow-runner-demo",
        contractVersion: "v1",
      },
    });
    expect(projected.statusCode).toBe(201);
    const body = projected.json();
    expect(body.status).toBe("sealed");
    expect(body.payload.tickets[0].requester_id).toMatch(/^tok_[a-f0-9]{24}$/);
    expect(JSON.stringify(body)).not.toContain("customer-991");
  });

  it("records valid AI output separately and quarantines invalid evidence", async () => {
    const seeded = await app.inject({
      method: "POST",
      url: "/v1/demo/seed",
      headers: identityHeaders,
    });
    const projectionResponse = await app.inject({
      method: "POST",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/backup-batches/${seeded.json().batch.id}/projections`,
      headers: identityHeaders,
      payload: {
        missionId: "ai-result-demo",
        runnerId: "shadow-runner-demo",
        contractVersion: "v1",
      },
    });
    const projectionId = projectionResponse.json().id;
    const valid = await app.inject({
      method: "POST",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/ai-results`,
      headers: runnerHeaders,
      payload: {
        projectionId,
        experimentId: "experiment-001",
        agentVersion: "demo-agent/0.1",
        toolVersion: "ticket-simulator/0.1",
        kind: "alert",
        evidenceRefs: ["ticket:CS-1842"],
        content: { severity: "high", summary: "Projected SLA breach risk." },
      },
    });
    expect(valid.statusCode).toBe(201);
    expect(valid.json().status).toBe("recorded");

    const quarantined = await app.inject({
      method: "POST",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/ai-results`,
      headers: runnerHeaders,
      payload: {
        projectionId,
        experimentId: "experiment-002",
        agentVersion: "demo-agent/0.1",
        toolVersion: "ticket-simulator/0.1",
        kind: "conclusion",
        evidenceRefs: ["ticket:UNKNOWN"],
        content: { authoritative: true, summary: "Untrusted assertion." },
      },
    });
    expect(quarantined.statusCode).toBe(201);
    expect(quarantined.json().status).toBe("quarantined");
    expect(quarantined.json().quarantineReasons).toHaveLength(2);
  });

  it("rejects D4 fields and event sequence gaps before persistence", async () => {
    const baseEvent = {
      sourceEventId: "unsafe-1",
      sequence: 1,
      eventType: "ticket.snapshot",
      entityType: "ticket",
      entityId: "UNSAFE-1",
      occurredAt: "2026-08-17T09:00:00.000Z",
      classification: ["D1"],
      payload: {
        ticket_id: "UNSAFE-1",
        state: "open",
        priority: "normal",
        customer_tier: "growth",
        sla_due_at: "2026-08-18T09:00:00.000Z",
        tags: [],
        queue: "general",
        requester_id: "customer-unsafe",
        created_at: "2026-08-17T09:00:00.000Z",
        updated_at: "2026-08-17T09:00:00.000Z",
      },
    };
    const secret = await app.inject({
      method: "POST",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/backup-batches`,
      headers: identityHeaders,
      payload: {
        source: "ticketing-sandbox",
        contractVersion: "v1",
        schemaVersion: "ticket-v1",
        cursor: { start: "unsafe:1", end: "unsafe:1" },
        events: [{ ...baseEvent, payload: { ...baseEvent.payload, api_key: "must-not-enter" } }],
      },
    });
    expect(secret.statusCode).toBe(422);
    expect(secret.json().error.code).toBe("D4_SECRET_REJECTED");

    const gap = await app.inject({
      method: "POST",
      url: `/v1/workspaces/${DEMO_WORKSPACE_ID}/backup-batches`,
      headers: identityHeaders,
      payload: {
        source: "ticketing-sandbox",
        contractVersion: "v1",
        schemaVersion: "ticket-v1",
        cursor: { start: "gap:1", end: "gap:3" },
        events: [baseEvent, { ...baseEvent, sourceEventId: "gap-3", sequence: 3 }],
      },
    });
    expect(gap.statusCode).toBe(422);
    expect(gap.json().error.code).toBe("EVENT_SEQUENCE_GAP");
  });

  it("enforces append-only enterprise events in PostgreSQL", async () => {
    await expect(
      pool.query("UPDATE enterprise_events SET payload = '{}'::jsonb"),
    ).rejects.toThrow(/append-only record cannot be mutated/);
  });

  it("publishes committed outbox events exactly once per drain", async () => {
    const messages: OutboxMessage[] = [];
    const result = await drainOutboxOnce(pool, {
      async publish(message) { messages.push(message); },
    }, 100);
    expect(result.published).toBeGreaterThan(0);
    expect(result.failed).toBe(0);
    expect(new Set(messages.map((message) => message.id)).size).toBe(messages.length);
    const remaining = await pool.query(
      "SELECT COUNT(*)::int AS count FROM outbox_events WHERE published_at IS NULL",
    );
    expect(remaining.rows[0].count).toBe(0);
  });
});
