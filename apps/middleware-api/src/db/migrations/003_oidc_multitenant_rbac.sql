CREATE TABLE IF NOT EXISTS organizations (
  id uuid PRIMARY KEY,
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  name text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO organizations (id, slug, name)
VALUES (
  '00000000-0000-4000-8000-000000000010',
  'agentobe-demo',
  'Agentobe Demo Organization'
)
ON CONFLICT (id) DO NOTHING;

ALTER TABLE workspaces
  ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES organizations(id);

UPDATE workspaces
SET organization_id = '00000000-0000-4000-8000-000000000010'
WHERE organization_id IS NULL;

ALTER TABLE workspaces
  ALTER COLUMN organization_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS workspaces_organization_idx
  ON workspaces (organization_id, created_at);

CREATE TABLE IF NOT EXISTS oidc_principals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  issuer text NOT NULL,
  subject text NOT NULL,
  email text,
  display_name text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz,
  UNIQUE (issuer, subject)
);

CREATE TABLE IF NOT EXISTS organization_memberships (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  principal_id uuid NOT NULL REFERENCES oidc_principals(id),
  roles text[] NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, principal_id),
  CHECK (cardinality(roles) > 0),
  CHECK (roles <@ ARRAY['owner', 'admin', 'operator', 'auditor', 'runner', 'viewer']::text[])
);

CREATE INDEX IF NOT EXISTS organization_memberships_principal_idx
  ON organization_memberships (principal_id, organization_id)
  WHERE status = 'active';
