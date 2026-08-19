CREATE TABLE IF NOT EXISTS simulation_missions (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  projection_id uuid NOT NULL REFERENCES ai_projections(id),
  backup_batch_id uuid NOT NULL REFERENCES backup_batches(id),
  trace_id uuid NOT NULL,
  name text NOT NULL,
  objective text NOT NULL,
  success_metric text NOT NULL,
  guard_metric text NOT NULL,
  constraints jsonb NOT NULL,
  budget jsonb NOT NULL,
  tool_scope text[] NOT NULL,
  owner_id text NOT NULL,
  runner_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('ready', 'running', 'paused', 'completed', 'cancelled', 'blocked')),
  status_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS simulation_experiments (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  mission_id uuid NOT NULL REFERENCES simulation_missions(id),
  projection_id uuid NOT NULL REFERENCES ai_projections(id),
  trace_id uuid NOT NULL,
  attempt integer NOT NULL,
  status text NOT NULL CHECK (status IN ('completed', 'inconclusive', 'failed', 'cancelled')),
  requested_branches integer NOT NULL CHECK (requested_branches BETWEEN 3 AND 4),
  agent_version text NOT NULL,
  tool_version text NOT NULL,
  input_hash text NOT NULL CHECK (input_hash ~ '^[a-f0-9]{64}$'),
  summary jsonb NOT NULL,
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (mission_id, attempt)
);

CREATE TABLE IF NOT EXISTS simulation_branches (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  experiment_id uuid NOT NULL REFERENCES simulation_experiments(id),
  name text NOT NULL,
  strategy text NOT NULL,
  ordinal integer NOT NULL,
  status text NOT NULL CHECK (status IN ('completed', 'inconclusive', 'failed')),
  confidence numeric(5,4) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  assumptions jsonb NOT NULL,
  blind_spots jsonb NOT NULL,
  metrics jsonb NOT NULL,
  metric_delta jsonb NOT NULL,
  replay_steps jsonb NOT NULL,
  shadow_state jsonb NOT NULL,
  state_hash text NOT NULL CHECK (state_hash ~ '^[a-f0-9]{64}$'),
  reproducible boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (experiment_id, ordinal),
  UNIQUE (experiment_id, strategy)
);

CREATE INDEX IF NOT EXISTS simulation_missions_workspace_created_idx
  ON simulation_missions (workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS simulation_experiments_mission_created_idx
  ON simulation_experiments (mission_id, created_at DESC);
CREATE INDEX IF NOT EXISTS simulation_branches_experiment_ordinal_idx
  ON simulation_branches (experiment_id, ordinal);

CREATE OR REPLACE FUNCTION protect_simulation_mission_definition() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'simulation mission cannot be deleted';
  END IF;
  IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
     OR NEW.projection_id IS DISTINCT FROM OLD.projection_id
     OR NEW.backup_batch_id IS DISTINCT FROM OLD.backup_batch_id
     OR NEW.trace_id IS DISTINCT FROM OLD.trace_id
     OR NEW.name IS DISTINCT FROM OLD.name
     OR NEW.objective IS DISTINCT FROM OLD.objective
     OR NEW.success_metric IS DISTINCT FROM OLD.success_metric
     OR NEW.guard_metric IS DISTINCT FROM OLD.guard_metric
     OR NEW.constraints IS DISTINCT FROM OLD.constraints
     OR NEW.budget IS DISTINCT FROM OLD.budget
     OR NEW.tool_scope IS DISTINCT FROM OLD.tool_scope
     OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
     OR NEW.runner_id IS DISTINCT FROM OLD.runner_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'simulation mission definition is immutable';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS simulation_missions_definition_immutable ON simulation_missions;
CREATE TRIGGER simulation_missions_definition_immutable
  BEFORE UPDATE OR DELETE ON simulation_missions
  FOR EACH ROW EXECUTE FUNCTION protect_simulation_mission_definition();

DROP TRIGGER IF EXISTS simulation_experiments_immutable ON simulation_experiments;
CREATE TRIGGER simulation_experiments_immutable
  BEFORE UPDATE OR DELETE ON simulation_experiments
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

DROP TRIGGER IF EXISTS simulation_branches_immutable ON simulation_branches;
CREATE TRIGGER simulation_branches_immutable
  BEFORE UPDATE OR DELETE ON simulation_branches
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
