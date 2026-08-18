import { createHash } from "node:crypto";
import { Type, type Static } from "@sinclair/typebox";

export const DataClassSchema = Type.Union([
  Type.Literal("D0"),
  Type.Literal("D1"),
  Type.Literal("D2"),
  Type.Literal("D3"),
  Type.Literal("D4"),
]);

export const CursorSchema = Type.Object(
  {
    start: Type.String({ minLength: 1 }),
    end: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);

export const EnterpriseEventInputSchema = Type.Object(
  {
    sourceEventId: Type.String({ minLength: 1, maxLength: 160 }),
    sequence: Type.Integer({ minimum: 1 }),
    eventType: Type.String({ minLength: 1, maxLength: 100 }),
    entityType: Type.Literal("ticket"),
    entityId: Type.String({ minLength: 1, maxLength: 160 }),
    occurredAt: Type.String({ format: "date-time" }),
    classification: Type.Array(DataClassSchema, { minItems: 1, uniqueItems: true }),
    payload: Type.Record(Type.String(), Type.Unknown()),
    checksum: Type.Optional(Type.String({ pattern: "^[a-f0-9]{64}$" })),
  },
  { additionalProperties: false },
);

export const CreateBackupBatchSchema = Type.Object(
  {
    source: Type.String({ minLength: 1, maxLength: 100 }),
    contractVersion: Type.String({ minLength: 1, maxLength: 40 }),
    schemaVersion: Type.String({ minLength: 1, maxLength: 40 }),
    cursor: CursorSchema,
    traceId: Type.Optional(Type.String({ format: "uuid" })),
    events: Type.Array(EnterpriseEventInputSchema, { minItems: 1, maxItems: 1000 }),
  },
  { additionalProperties: false },
);

export const CreateProjectionSchema = Type.Object(
  {
    missionId: Type.String({ minLength: 1, maxLength: 160 }),
    runnerId: Type.String({ minLength: 1, maxLength: 160 }),
    contractVersion: Type.String({ minLength: 1, maxLength: 40 }),
  },
  { additionalProperties: false },
);

export const ReplicationContractRulesSchema = Type.Object(
  {
    entity: Type.Literal("ticket"),
    mode: Type.Literal("snapshot_plus_events"),
    allow: Type.Array(Type.String({ minLength: 1 }), { minItems: 1, uniqueItems: true }),
    tokenize: Type.Array(Type.String({ minLength: 1 }), { uniqueItems: true }),
    deny: Type.Array(Type.String({ minLength: 1 }), { minItems: 1, uniqueItems: true }),
    simulation_use: Type.Array(Type.String({ minLength: 1 }), {
      minItems: 1,
      uniqueItems: true,
    }),
  },
  { additionalProperties: false },
);

export const CreateReplicationContractSchema = Type.Object(
  {
    source: Type.String({ minLength: 1, maxLength: 100 }),
    version: Type.String({ minLength: 1, maxLength: 40 }),
    rules: ReplicationContractRulesSchema,
    freshnessSloSeconds: Type.Integer({ minimum: 30, maximum: 86_400 }),
    retentionDays: Type.Integer({ minimum: 1, maximum: 3_650 }),
  },
  { additionalProperties: false },
);

export const ChangeReplicationSourceStateSchema = Type.Object(
  {
    status: Type.Union([Type.Literal("active"), Type.Literal("paused")]),
    reason: Type.String({ minLength: 3, maxLength: 500 }),
  },
  { additionalProperties: false },
);

export const AIResultKindSchema = Type.Union([
  Type.Literal("simulation_event"),
  Type.Literal("alert"),
  Type.Literal("conclusion"),
  Type.Literal("prediction"),
  Type.Literal("action_proposal"),
]);

export const CreateAIResultSchema = Type.Object(
  {
    projectionId: Type.String({ format: "uuid" }),
    experimentId: Type.String({ minLength: 1, maxLength: 160 }),
    agentVersion: Type.String({ minLength: 1, maxLength: 100 }),
    toolVersion: Type.String({ minLength: 1, maxLength: 100 }),
    kind: AIResultKindSchema,
    evidenceRefs: Type.Array(Type.String({ minLength: 1, maxLength: 200 }), {
      minItems: 1,
      maxItems: 100,
      uniqueItems: true,
    }),
    content: Type.Record(Type.String(), Type.Unknown()),
  },
  { additionalProperties: false },
);

export type DataClass = Static<typeof DataClassSchema>;
export type EnterpriseEventInput = Static<typeof EnterpriseEventInputSchema>;
export type CreateBackupBatch = Static<typeof CreateBackupBatchSchema>;
export type CreateProjection = Static<typeof CreateProjectionSchema>;
export type CreateAIResult = Static<typeof CreateAIResultSchema>;
export type CreateReplicationContract = Static<typeof CreateReplicationContractSchema>;
export type ChangeReplicationSourceState = Static<typeof ChangeReplicationSourceStateSchema>;

function normalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, normalize(entry)]),
    );
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalize(value));
}

export function sha256(value: unknown): string {
  const input = typeof value === "string" ? value : canonicalJson(value);
  return createHash("sha256").update(input).digest("hex");
}

export const DEMO_WORKSPACE_ID = "00000000-0000-4000-8000-000000000001";
