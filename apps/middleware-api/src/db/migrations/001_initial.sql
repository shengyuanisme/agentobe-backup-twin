CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS workspaces (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  risk_profile text NOT NULL DEFAULT 'demo',
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'stopped')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS replication_contracts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  source text NOT NULL,
  version text NOT NULL,
  rules jsonb NOT NULL,
  freshness_slo_seconds integer NOT NULL,
  retention_days integer NOT NULL,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, source, version)
);

CREATE TABLE IF NOT EXISTS backup_batches (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  trace_id uuid NOT NULL,
  source text NOT NULL,
  contract_version text NOT NULL,
  schema_version text NOT NULL,
  cursor_start text NOT NULL,
  cursor_end text NOT NULL,
  status text NOT NULL CHECK (status IN ('sealed', 'degraded', 'failed')),
  manifest jsonb NOT NULL,
  manifest_hash text NOT NULL CHECK (manifest_hash ~ '^[a-f0-9]{64}$'),
  record_count integer NOT NULL CHECK (record_count > 0),
  classifications text[] NOT NULL,
  sealed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, source, cursor_end)
);

CREATE TABLE IF NOT EXISTS enterprise_events (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  backup_batch_id uuid NOT NULL REFERENCES backup_batches(id),
  source_event_id text NOT NULL,
  sequence bigint NOT NULL,
  event_type text NOT NULL,
  entity_type text NOT NULL,
  entity_id text NOT NULL,
  occurred_at timestamptz NOT NULL,
  classification text[] NOT NULL,
  payload jsonb NOT NULL,
  payload_checksum text NOT NULL CHECK (payload_checksum ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, source_event_id),
  UNIQUE (backup_batch_id, sequence)
);

CREATE TABLE IF NOT EXISTS ai_projections (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  backup_batch_id uuid NOT NULL REFERENCES backup_batches(id),
  trace_id uuid NOT NULL,
  mission_id text NOT NULL,
  runner_id text NOT NULL,
  contract_version text NOT NULL,
  version integer NOT NULL,
  status text NOT NULL CHECK (status IN ('sealed', 'revoked')),
  payload jsonb NOT NULL,
  projection_hash text NOT NULL CHECK (projection_hash ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (backup_batch_id, mission_id, runner_id, version)
);

CREATE TABLE IF NOT EXISTS ai_results (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  backup_batch_id uuid NOT NULL REFERENCES backup_batches(id),
  projection_id uuid NOT NULL REFERENCES ai_projections(id),
  trace_id uuid NOT NULL,
  experiment_id text NOT NULL,
  agent_version text NOT NULL,
  tool_version text NOT NULL,
  kind text NOT NULL,
  status text NOT NULL CHECK (status IN ('recorded', 'quarantined', 'pending_compilation')),
  evidence_refs text[] NOT NULL,
  content jsonb NOT NULL,
  content_hash text NOT NULL CHECK (content_hash ~ '^[a-f0-9]{64}$'),
  quarantine_reasons text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  trace_id uuid NOT NULL,
  plane text NOT NULL CHECK (plane IN ('enterprise', 'shadow', 'control')),
  actor_id text NOT NULL,
  event_type text NOT NULL,
  object_type text NOT NULL,
  object_id text NOT NULL,
  classification text[] NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS outbox_events (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  trace_id uuid NOT NULL,
  topic text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz
);

CREATE INDEX IF NOT EXISTS backup_batches_workspace_created_idx
  ON backup_batches (workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS enterprise_events_entity_idx
  ON enterprise_events (workspace_id, entity_type, entity_id, sequence);
CREATE INDEX IF NOT EXISTS audit_events_trace_idx
  ON audit_events (trace_id, created_at);
CREATE INDEX IF NOT EXISTS outbox_events_pending_idx
  ON outbox_events (created_at) WHERE published_at IS NULL;

CREATE OR REPLACE FUNCTION reject_immutable_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'append-only record cannot be mutated';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS enterprise_events_immutable ON enterprise_events;
CREATE TRIGGER enterprise_events_immutable
  BEFORE UPDATE OR DELETE ON enterprise_events
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DROP TRIGGER IF EXISTS ai_projections_immutable ON ai_projections;
CREATE TRIGGER ai_projections_immutable
  BEFORE UPDATE OR DELETE ON ai_projections
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DROP TRIGGER IF EXISTS ai_results_immutable ON ai_results;
CREATE TRIGGER ai_results_immutable
  BEFORE UPDATE OR DELETE ON ai_results
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DROP TRIGGER IF EXISTS audit_events_immutable ON audit_events;
CREATE TRIGGER audit_events_immutable
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

INSERT INTO workspaces (id, name, risk_profile)
VALUES ('00000000-0000-4000-8000-000000000001', 'Agentobe Demo Workspace', 'demo')
ON CONFLICT (id) DO NOTHING;

INSERT INTO replication_contracts (
  workspace_id,
  source,
  version,
  rules,
  freshness_slo_seconds,
  retention_days
)
VALUES (
  '00000000-0000-4000-8000-000000000001',
  'ticketing-sandbox',
  'v1',
  '{
    "entity": "ticket",
    "mode": "snapshot_plus_events",
    "allow": ["ticket_id", "state", "priority", "customer_tier", "sla_due_at", "tags", "queue", "requester_id", "created_at", "updated_at"],
    "tokenize": ["requester_id"],
    "deny": ["email_body", "attachments", "access_token", "api_key", "password", "private_key"],
    "simulation_use": ["triage", "prioritization", "capacity_planning"]
  }'::jsonb,
  300,
  30
)
ON CONFLICT (workspace_id, source, version) DO NOTHING;
