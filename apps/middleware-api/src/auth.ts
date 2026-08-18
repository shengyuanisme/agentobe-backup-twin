import type { FastifyRequest } from "fastify";
import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
} from "jose";
import type pg from "pg";
import { AppError } from "./errors.js";

export const roles = ["owner", "admin", "operator", "auditor", "runner", "viewer"] as const;
export type Role = (typeof roles)[number];

export type Permission =
  | "workspace:read"
  | "backup:write"
  | "backup:verify"
  | "contract:write"
  | "source:control"
  | "projection:write"
  | "ai-result:write"
  | "audit:read"
  | "membership:read"
  | "membership:write";

const allPermissions: Permission[] = [
  "workspace:read", "backup:write", "backup:verify", "contract:write",
  "source:control", "projection:write", "ai-result:write", "audit:read",
  "membership:read", "membership:write",
];

const rolePermissions: Record<Role, ReadonlySet<Permission>> = {
  owner: new Set(allPermissions),
  admin: new Set(allPermissions),
  operator: new Set([
    "workspace:read", "backup:write", "backup:verify", "source:control",
    "projection:write",
  ]),
  auditor: new Set(["workspace:read", "backup:verify", "audit:read", "membership:read"]),
  runner: new Set(["workspace:read", "ai-result:write"]),
  viewer: new Set(["workspace:read"]),
};

export interface Identity {
  issuer: string;
  subject: string;
  email?: string;
  displayName?: string;
}

export interface AccessTokenVerifier {
  verify(token: string): Promise<Identity>;
}

export class OidcAccessTokenVerifier implements AccessTokenVerifier {
  private constructor(
    private readonly issuer: string,
    private readonly audience: string,
    private readonly jwks: ReturnType<typeof createRemoteJWKSet>,
    private readonly algorithms: string[],
  ) {}

  static async create(options: {
    issuer: string;
    audience: string;
    jwksUri?: string;
    algorithms?: string[];
  }): Promise<OidcAccessTokenVerifier> {
    const issuer = options.issuer;
    let jwksUri = options.jwksUri;
    if (!jwksUri) {
      const discoveryBase = issuer.endsWith("/") ? issuer.slice(0, -1) : issuer;
      const response = await fetch(`${discoveryBase}/.well-known/openid-configuration`);
      if (!response.ok) throw new Error(`OIDC discovery failed with HTTP ${response.status}.`);
      const metadata = await response.json() as { issuer?: string; jwks_uri?: string };
      if (metadata.issuer !== issuer || !metadata.jwks_uri) {
        throw new Error("OIDC discovery metadata has an unexpected issuer or no jwks_uri.");
      }
      jwksUri = metadata.jwks_uri;
    }
    return new OidcAccessTokenVerifier(
      issuer,
      options.audience,
      createRemoteJWKSet(new URL(jwksUri)),
      options.algorithms ?? ["RS256"],
    );
  }

  async verify(token: string): Promise<Identity> {
    try {
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: this.issuer,
        audience: this.audience,
        algorithms: this.algorithms,
      });
      return identityFromClaims(payload);
    } catch {
      throw new AppError(401, "ACCESS_TOKEN_INVALID", "The OIDC access token is invalid or expired.");
    }
  }
}

export class StaticAccessTokenVerifier implements AccessTokenVerifier {
  constructor(private readonly identities: Record<string, Identity>) {}

  async verify(token: string): Promise<Identity> {
    const identity = this.identities[token];
    if (!identity) throw new AppError(401, "ACCESS_TOKEN_INVALID", "The access token is invalid.");
    return identity;
  }
}

export class AuthorizationService {
  constructor(
    private readonly pool: pg.Pool,
    private readonly verifier: AccessTokenVerifier,
  ) {}

  async authenticate(request: FastifyRequest): Promise<Identity> {
    const authorization = request.headers.authorization;
    if (!authorization?.startsWith("Bearer ")) {
      throw new AppError(401, "BEARER_TOKEN_REQUIRED", "A Bearer access token is required.");
    }
    const token = authorization.slice("Bearer ".length).trim();
    if (!token) throw new AppError(401, "BEARER_TOKEN_REQUIRED", "A Bearer access token is required.");
    return this.verifier.verify(token);
  }

  async authorizeWorkspace(
    request: FastifyRequest,
    workspaceId: string,
    permission: Permission,
  ) {
    const identity = await this.authenticate(request);
    const result = await this.pool.query<{
      organization_id: string;
      organization_name: string;
      workspace_name: string;
      roles: Role[];
    }>(
      `SELECT o.id AS organization_id, o.name AS organization_name,
              w.name AS workspace_name, m.roles
       FROM oidc_principals p
       JOIN organization_memberships m ON m.principal_id = p.id AND m.status = 'active'
       JOIN organizations o ON o.id = m.organization_id AND o.status = 'active'
       JOIN workspaces w ON w.organization_id = o.id AND w.status = 'active'
       WHERE p.issuer = $1 AND p.subject = $2 AND w.id = $3`,
      [identity.issuer, identity.subject, workspaceId],
    );
    const membership = result.rows[0];
    if (!membership) {
      throw new AppError(403, "TENANT_ACCESS_DENIED", "The identity is not an active member of this workspace tenant.");
    }
    if (!membership.roles.some((role) => rolePermissions[role]?.has(permission))) {
      throw new AppError(403, "PERMISSION_DENIED", `Permission ${permission} is required.`);
    }
    await this.touchPrincipal(identity);
    return { identity, ...membership };
  }

  async authorizeOrganization(
    request: FastifyRequest,
    organizationId: string,
    permission: Permission,
  ) {
    const identity = await this.authenticate(request);
    const result = await this.pool.query<{ organization_name: string; roles: Role[] }>(
      `SELECT o.name AS organization_name, m.roles
       FROM oidc_principals p
       JOIN organization_memberships m ON m.principal_id = p.id AND m.status = 'active'
       JOIN organizations o ON o.id = m.organization_id AND o.status = 'active'
       WHERE p.issuer = $1 AND p.subject = $2 AND o.id = $3`,
      [identity.issuer, identity.subject, organizationId],
    );
    const membership = result.rows[0];
    if (!membership) throw new AppError(403, "TENANT_ACCESS_DENIED", "Organization access denied.");
    if (!membership.roles.some((role) => rolePermissions[role]?.has(permission))) {
      throw new AppError(403, "PERMISSION_DENIED", `Permission ${permission} is required.`);
    }
    await this.touchPrincipal(identity);
    return { identity, organizationId, ...membership };
  }

  async describeIdentity(request: FastifyRequest) {
    const identity = await this.authenticate(request);
    const result = await this.pool.query<{
      organization_id: string;
      organization_name: string;
      roles: Role[];
      workspace_id: string;
      workspace_name: string;
    }>(
      `SELECT o.id AS organization_id, o.name AS organization_name, m.roles,
              w.id AS workspace_id, w.name AS workspace_name
       FROM oidc_principals p
       JOIN organization_memberships m ON m.principal_id = p.id AND m.status = 'active'
       JOIN organizations o ON o.id = m.organization_id AND o.status = 'active'
       JOIN workspaces w ON w.organization_id = o.id AND w.status = 'active'
       WHERE p.issuer = $1 AND p.subject = $2
       ORDER BY o.name, w.name`,
      [identity.issuer, identity.subject],
    );
    if (result.rows.length === 0) {
      throw new AppError(403, "TENANT_ACCESS_DENIED", "No active Agentobe tenant membership was found.");
    }
    await this.touchPrincipal(identity);
    return {
      identity,
      workspaces: result.rows.map((row) => ({
        organizationId: row.organization_id,
        organizationName: row.organization_name,
        workspaceId: row.workspace_id,
        workspaceName: row.workspace_name,
        roles: row.roles,
        permissions: permissionsForRoles(row.roles),
      })),
    };
  }

  async listMemberships(organizationId: string) {
    const result = await this.pool.query(
      `SELECT p.id AS principal_id, p.issuer, p.subject, p.email, p.display_name, m.roles, m.status,
              m.created_at, m.updated_at
       FROM organization_memberships m
       JOIN oidc_principals p ON p.id = m.principal_id
       WHERE m.organization_id = $1
       ORDER BY COALESCE(p.display_name, p.email, p.subject)`,
      [organizationId],
    );
    return result.rows;
  }

  async upsertMembership(input: {
    organizationId: string;
    issuer: string;
    subject: string;
    email?: string;
    displayName?: string;
    roles: Role[];
    actorId: string;
    actorRoles: Role[];
  }) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const principal = await client.query<{ id: string }>(
        `INSERT INTO oidc_principals (issuer, subject, email, display_name)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT (issuer, subject) DO UPDATE
         SET email = COALESCE(EXCLUDED.email, oidc_principals.email),
             display_name = COALESCE(EXCLUDED.display_name, oidc_principals.display_name)
         RETURNING id`,
        [input.issuer, input.subject, input.email ?? null, input.displayName ?? null],
      );
      const existing = await client.query<{ roles: Role[] }>(
        `SELECT roles FROM organization_memberships
         WHERE organization_id = $1 AND principal_id = $2 FOR UPDATE`,
        [input.organizationId, principal.rows[0]!.id],
      );
      const ownerActing = input.actorRoles.includes("owner");
      if ((input.roles.includes("owner") || existing.rows[0]?.roles.includes("owner")) && !ownerActing) {
        throw new AppError(403, "OWNER_ROLE_REQUIRED", "Only an owner can grant or modify an owner membership.");
      }
      if (existing.rows[0]?.roles.includes("owner") && !input.roles.includes("owner")) {
        await this.assertAnotherOwner(client, input.organizationId, principal.rows[0]!.id);
      }
      const membership = await client.query(
        `INSERT INTO organization_memberships (
           organization_id, principal_id, roles, status, created_by
         ) VALUES ($1,$2,$3,'active',$4)
         ON CONFLICT (organization_id, principal_id) DO UPDATE
         SET roles = EXCLUDED.roles, status = 'active', updated_at = now()
         RETURNING organization_id, roles, status, created_at, updated_at`,
        [input.organizationId, principal.rows[0]!.id, [...new Set(input.roles)], input.actorId],
      );
      await client.query("COMMIT");
      return membership.rows[0];
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async ensureBootstrapOwner(input: {
    organizationId: string;
    issuer: string;
    subject: string;
    email?: string;
    displayName?: string;
  }) {
    const existingOwner = await this.pool.query(
      `SELECT 1 FROM organization_memberships
       WHERE organization_id = $1 AND status = 'active'
         AND roles @> ARRAY['owner']::text[]
       LIMIT 1`,
      [input.organizationId],
    );
    if (existingOwner.rows[0]) return { created: false };
    const membership = await this.upsertMembership({
      ...input,
      roles: ["owner"],
      actorId: "system:bootstrap",
      actorRoles: ["owner"],
    });
    return { created: true, membership };
  }

  async changeMembershipStatus(input: {
    organizationId: string;
    principalId: string;
    status: "active" | "suspended";
    actorRoles: Role[];
  }) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const membership = await client.query<{ roles: Role[] }>(
        `SELECT roles FROM organization_memberships
         WHERE organization_id = $1 AND principal_id = $2 FOR UPDATE`,
        [input.organizationId, input.principalId],
      );
      const current = membership.rows[0];
      if (!current) throw new AppError(404, "MEMBERSHIP_NOT_FOUND", "Membership not found.");
      if (current.roles.includes("owner") && !input.actorRoles.includes("owner")) {
        throw new AppError(403, "OWNER_ROLE_REQUIRED", "Only an owner can modify an owner membership.");
      }
      if (current.roles.includes("owner") && input.status === "suspended") {
        await this.assertAnotherOwner(client, input.organizationId, input.principalId);
      }
      const updated = await client.query(
        `UPDATE organization_memberships
         SET status = $3, updated_at = now()
         WHERE organization_id = $1 AND principal_id = $2
         RETURNING organization_id, principal_id, roles, status, updated_at`,
        [input.organizationId, input.principalId, input.status],
      );
      await client.query("COMMIT");
      return updated.rows[0];
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  private async touchPrincipal(identity: Identity) {
    await this.pool.query(
      `UPDATE oidc_principals
       SET email = COALESCE($3, email), display_name = COALESCE($4, display_name),
           last_seen_at = now()
       WHERE issuer = $1 AND subject = $2`,
      [identity.issuer, identity.subject, identity.email ?? null, identity.displayName ?? null],
    );
  }

  private async assertAnotherOwner(
    client: pg.PoolClient,
    organizationId: string,
    excludedPrincipalId: string,
  ) {
    const owners = await client.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count
       FROM organization_memberships
       WHERE organization_id = $1 AND principal_id <> $2 AND status = 'active'
         AND roles @> ARRAY['owner']::text[]`,
      [organizationId, excludedPrincipalId],
    );
    if (Number(owners.rows[0]!.count) === 0) {
      throw new AppError(409, "LAST_OWNER_REQUIRED", "The organization must retain at least one active owner.");
    }
  }
}

function identityFromClaims(payload: JWTPayload): Identity {
  if (!payload.iss || !payload.sub) {
    throw new AppError(401, "ACCESS_TOKEN_INVALID", "The token must contain iss and sub claims.");
  }
  const email = typeof payload.email === "string" ? payload.email : undefined;
  const displayName = typeof payload.name === "string" ? payload.name : undefined;
  return {
    issuer: payload.iss,
    subject: payload.sub,
    ...(email ? { email } : {}),
    ...(displayName ? { displayName } : {}),
  };
}

function permissionsForRoles(memberRoles: Role[]): Permission[] {
  return [...new Set(memberRoles.flatMap((role) => [...(rolePermissions[role] ?? [])]))].sort();
}
