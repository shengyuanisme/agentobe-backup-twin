ALTER TABLE replication_contracts
  ADD COLUMN IF NOT EXISTS created_by text NOT NULL DEFAULT 'migration';

CREATE TABLE IF NOT EXISTS replication_source_controls (
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  source text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'paused')),
  reason text NOT NULL,
  version bigint NOT NULL DEFAULT 1,
  updated_by text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, source)
);

CREATE TABLE IF NOT EXISTS source_backup_objects (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  backup_batch_id uuid NOT NULL UNIQUE REFERENCES backup_batches(id),
  object_key text NOT NULL UNIQUE,
  storage_driver text NOT NULL CHECK (storage_driver IN ('file', 'spaces', 'memory')),
  encryption_algorithm text NOT NULL,
  key_wrap_algorithm text NOT NULL,
  key_version text NOT NULL,
  plaintext_hash text NOT NULL CHECK (plaintext_hash ~ '^[a-f0-9]{64}$'),
  ciphertext_hash text NOT NULL CHECK (ciphertext_hash ~ '^[a-f0-9]{64}$'),
  size_bytes bigint NOT NULL CHECK (size_bytes > 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE outbox_events
  ADD COLUMN IF NOT EXISTS attempts integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS last_error text;

CREATE INDEX IF NOT EXISTS outbox_events_ready_idx
  ON outbox_events (next_attempt_at, created_at)
  WHERE published_at IS NULL;

DROP TRIGGER IF EXISTS replication_contracts_immutable ON replication_contracts;
CREATE TRIGGER replication_contracts_immutable
  BEFORE UPDATE OR DELETE ON replication_contracts
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DROP TRIGGER IF EXISTS source_backup_objects_immutable ON source_backup_objects;
CREATE TRIGGER source_backup_objects_immutable
  BEFORE UPDATE OR DELETE ON source_backup_objects
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

INSERT INTO replication_source_controls (
  workspace_id, source, status, reason, updated_by
)
VALUES (
  '00000000-0000-4000-8000-000000000001',
  'ticketing-sandbox',
  'active',
  'Initial demo source activation',
  'migration'
)
ON CONFLICT (workspace_id, source) DO NOTHING;
