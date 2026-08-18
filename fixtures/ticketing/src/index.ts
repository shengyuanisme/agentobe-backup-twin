import { sha256, type CreateBackupBatch } from "@agentobe/contracts";

const baseEvents = [
  {
    sourceEventId: "demo-ticket-1842-created",
    sequence: 1,
    eventType: "ticket.snapshot",
    entityType: "ticket" as const,
    entityId: "CS-1842",
    occurredAt: "2026-08-17T08:00:00.000Z",
    classification: ["D1", "D2"] as const,
    payload: {
      ticket_id: "CS-1842",
      state: "open",
      priority: "high",
      customer_tier: "enterprise",
      sla_due_at: "2026-08-17T14:00:00.000Z",
      tags: ["regional-queue", "backlog"],
      queue: "apac-general",
      requester_id: "customer-991",
      created_at: "2026-08-17T07:10:00.000Z",
      updated_at: "2026-08-17T08:00:00.000Z",
    },
  },
  {
    sourceEventId: "demo-ticket-1843-created",
    sequence: 2,
    eventType: "ticket.snapshot",
    entityType: "ticket" as const,
    entityId: "CS-1843",
    occurredAt: "2026-08-17T08:01:00.000Z",
    classification: ["D1", "D2"] as const,
    payload: {
      ticket_id: "CS-1843",
      state: "open",
      priority: "normal",
      customer_tier: "growth",
      sla_due_at: "2026-08-18T08:00:00.000Z",
      tags: ["billing-question"],
      queue: "apac-general",
      requester_id: "customer-447",
      created_at: "2026-08-17T07:25:00.000Z",
      updated_at: "2026-08-17T08:01:00.000Z",
    },
  },
  {
    sourceEventId: "demo-ticket-1844-created",
    sequence: 3,
    eventType: "ticket.snapshot",
    entityType: "ticket" as const,
    entityId: "CS-1844",
    occurredAt: "2026-08-17T08:02:00.000Z",
    classification: ["D1", "D2"] as const,
    payload: {
      ticket_id: "CS-1844",
      state: "pending",
      priority: "normal",
      customer_tier: "enterprise",
      sla_due_at: "2026-08-17T18:00:00.000Z",
      tags: ["integration"],
      queue: "integrations",
      requester_id: "customer-118",
      created_at: "2026-08-17T06:55:00.000Z",
      updated_at: "2026-08-17T08:02:00.000Z",
    },
  },
];

export function buildSyntheticBackupBatch(): CreateBackupBatch {
  return {
    source: "ticketing-sandbox",
    contractVersion: "v1",
    schemaVersion: "ticket-v1",
    cursor: { start: "demo:1", end: "demo:3" },
    events: baseEvents.map((event) => ({
      ...event,
      classification: [...event.classification],
      checksum: sha256(event.payload),
    })),
  };
}
