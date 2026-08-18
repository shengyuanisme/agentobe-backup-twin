import type { Pool } from "pg";
import Fastify, { type FastifyRequest } from "fastify";
import swagger from "@fastify/swagger";
import swaggerUi from "@fastify/swagger-ui";
import cors from "@fastify/cors";
import { Type } from "@sinclair/typebox";
import {
  CreateAIResultSchema,
  CreateBackupBatchSchema,
  CreateProjectionSchema,
  CreateReplicationContractSchema,
  ChangeReplicationSourceStateSchema,
  DEMO_WORKSPACE_ID,
  type CreateAIResult,
  type CreateBackupBatch,
  type CreateProjection,
  type CreateReplicationContract,
  type ChangeReplicationSourceState,
} from "@agentobe/contracts";
import { buildSyntheticBackupBatch } from "@agentobe/ticketing-fixtures";
import { AppError } from "./errors.js";
import {
  AuthorizationService,
  roles,
  type AccessTokenVerifier,
  type Permission,
  type Role,
} from "./auth.js";
import { MiddlewareStore } from "./store.js";
import type { EncryptedSourceVault } from "./vault.js";

const WorkspaceParamsSchema = Type.Object({
  workspaceId: Type.String({ format: "uuid" }),
});
const BatchParamsSchema = Type.Object({
  workspaceId: Type.String({ format: "uuid" }),
  batchId: Type.String({ format: "uuid" }),
});
const ProjectionParamsSchema = Type.Object({
  workspaceId: Type.String({ format: "uuid" }),
  projectionId: Type.String({ format: "uuid" }),
});
const TraceParamsSchema = Type.Object({
  workspaceId: Type.String({ format: "uuid" }),
  traceId: Type.String({ format: "uuid" }),
});
const SourceParamsSchema = Type.Object({
  workspaceId: Type.String({ format: "uuid" }),
  source: Type.String({ minLength: 1, maxLength: 100 }),
});
const OrganizationParamsSchema = Type.Object({
  organizationId: Type.String({ format: "uuid" }),
});
const MembershipParamsSchema = Type.Object({
  organizationId: Type.String({ format: "uuid" }),
  principalId: Type.String({ format: "uuid" }),
});
const MembershipStateBodySchema = Type.Object({
  status: Type.Union([Type.Literal("active"), Type.Literal("suspended")]),
}, { additionalProperties: false });
const MembershipBodySchema = Type.Object({
  issuer: Type.String({ format: "uri", maxLength: 500 }),
  subject: Type.String({ minLength: 1, maxLength: 500 }),
  email: Type.Optional(Type.String({ format: "email", maxLength: 320 })),
  displayName: Type.Optional(Type.String({ minLength: 1, maxLength: 200 })),
  roles: Type.Array(Type.Union(roles.map((role) => Type.Literal(role))), {
    minItems: 1,
    uniqueItems: true,
  }),
}, { additionalProperties: false });

export async function buildServer(options: {
  pool: Pool;
  projectionTokenKey: string;
  sourceVault: EncryptedSourceVault;
  tokenVerifier: AccessTokenVerifier;
  consoleOrigins?: string[];
  logLevel?: string;
}) {
  const app = Fastify({
    logger: options.logLevel === "silent" ? false : { level: options.logLevel ?? "info" },
    ajv: { customOptions: { removeAdditional: false } },
  });
  const store = new MiddlewareStore(
    options.pool,
    options.projectionTokenKey,
    options.sourceVault,
  );
  const authorization = new AuthorizationService(options.pool, options.tokenVerifier);
  const authorize = (
    request: FastifyRequest,
    workspaceId: string,
    permission: Permission,
  ) => authorization.authorizeWorkspace(request, workspaceId, permission);

  await app.register(cors, {
    origin: options.consoleOrigins ?? [],
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["authorization", "content-type"],
  });

  await app.register(swagger, {
    openapi: {
      info: {
        title: "Agentobe Backup & Simulation Middleware API",
        version: "0.1.0",
      },
      components: {
        securitySchemes: {
          oidcBearer: {
            type: "http",
            scheme: "bearer",
            bearerFormat: "JWT",
          },
        },
      },
    },
  });
  await app.register(swaggerUi, { routePrefix: "/docs" });

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof AppError) {
      return reply.status(error.statusCode).send({
        error: { code: error.code, message: error.message, details: error.details },
      });
    }
    const validationError = error as { validation?: unknown; message?: string };
    if (validationError.validation) {
      return reply.status(400).send({
        error: {
          code: "REQUEST_VALIDATION_FAILED",
          message: validationError.message ?? "Request validation failed.",
        },
      });
    }
    app.log.error(error);
    return reply.status(500).send({
      error: { code: "INTERNAL_ERROR", message: "Unexpected middleware failure." },
    });
  });

  app.get("/health", async () => {
    await options.pool.query("SELECT 1");
    return { status: "ok", service: "backup-simulation-middleware" };
  });

  app.get(
    "/v1/me",
    { schema: { security: [{ oidcBearer: [] }] } },
    async (request) => authorization.describeIdentity(request),
  );

  app.get<{ Params: { organizationId: string } }>(
    "/v1/organizations/:organizationId/memberships",
    {
      schema: {
        params: OrganizationParamsSchema,
        security: [{ oidcBearer: [] }],
      },
    },
    async (request) => {
      await authorization.authorizeOrganization(
        request,
        request.params.organizationId,
        "membership:read",
      );
      return { items: await authorization.listMemberships(request.params.organizationId) };
    },
  );

  app.post<{
    Params: { organizationId: string };
    Body: {
      issuer: string;
      subject: string;
      email?: string;
      displayName?: string;
      roles: Role[];
    };
  }>(
    "/v1/organizations/:organizationId/memberships",
    {
      schema: {
        params: OrganizationParamsSchema,
        body: MembershipBodySchema,
        security: [{ oidcBearer: [] }],
      },
    },
    async (request, reply) => {
      const context = await authorization.authorizeOrganization(
        request,
        request.params.organizationId,
        "membership:write",
      );
      const membership = await authorization.upsertMembership({
        organizationId: request.params.organizationId,
        issuer: request.body.issuer,
        subject: request.body.subject,
        ...(request.body.email ? { email: request.body.email } : {}),
        ...(request.body.displayName ? { displayName: request.body.displayName } : {}),
        roles: request.body.roles,
        actorId: context.identity.subject,
        actorRoles: context.roles,
      });
      return reply.status(201).send(membership);
    },
  );

  app.post<{
    Params: { organizationId: string; principalId: string };
    Body: { status: "active" | "suspended" };
  }>(
    "/v1/organizations/:organizationId/memberships/:principalId/state",
    {
      schema: {
        params: MembershipParamsSchema,
        body: MembershipStateBodySchema,
        security: [{ oidcBearer: [] }],
      },
    },
    async (request) => {
      const context = await authorization.authorizeOrganization(
        request,
        request.params.organizationId,
        "membership:write",
      );
      return authorization.changeMembershipStatus({
        organizationId: request.params.organizationId,
        principalId: request.params.principalId,
        status: request.body.status,
        actorRoles: context.roles,
      });
    },
  );

  app.post("/v1/demo/seed", async (request, reply) => {
    const context = await authorize(request, DEMO_WORKSPACE_ID, "backup:write");
    const actor = context.identity.subject;
    const input = buildSyntheticBackupBatch();
    const existing = await store.findBatchByCursor(
      DEMO_WORKSPACE_ID,
      input.source,
      input.cursor.end,
    );
    const batch = existing ?? await store.createBackupBatch(DEMO_WORKSPACE_ID, input, actor);
    return reply.status(existing ? 200 : 201).send({
      workspaceId: DEMO_WORKSPACE_ID,
      created: !existing,
      batch,
    });
  });

  app.post<{ Params: { workspaceId: string }; Body: CreateBackupBatch }>(
    "/v1/workspaces/:workspaceId/backup-batches",
    {
      schema: {
        params: WorkspaceParamsSchema,
        body: CreateBackupBatchSchema,
        security: [{ oidcBearer: [] }],
      },
    },
    async (request, reply) => {
      const context = await authorize(request, request.params.workspaceId, "backup:write");
      const batch = await store.createBackupBatch(
        request.params.workspaceId,
        request.body,
        context.identity.subject,
      );
      return reply.status(201).send(batch);
    },
  );

  app.get<{ Params: { workspaceId: string } }>(
    "/v1/workspaces/:workspaceId/backup-batches",
    { schema: { params: WorkspaceParamsSchema, security: [{ oidcBearer: [] }] } },
    async (request) => {
      await authorize(request, request.params.workspaceId, "workspace:read");
      return { items: await store.listBackupBatches(request.params.workspaceId) };
    },
  );

  app.get<{ Params: { workspaceId: string } }>(
    "/v1/workspaces/:workspaceId/replication-sources",
    { schema: { params: WorkspaceParamsSchema, security: [{ oidcBearer: [] }] } },
    async (request) => {
      await authorize(request, request.params.workspaceId, "workspace:read");
      return { items: await store.listReplicationSources(request.params.workspaceId) };
    },
  );

  app.get<{ Params: { workspaceId: string }; Querystring: { source?: string } }>(
    "/v1/workspaces/:workspaceId/replication-contracts",
    {
      schema: {
        params: WorkspaceParamsSchema,
        querystring: Type.Object({ source: Type.Optional(Type.String({ maxLength: 100 })) }),
        security: [{ oidcBearer: [] }],
      },
    },
    async (request) => {
      await authorize(request, request.params.workspaceId, "workspace:read");
      return {
        items: await store.listReplicationContracts(
          request.params.workspaceId,
          request.query.source,
        ),
      };
    },
  );

  app.post<{ Params: { workspaceId: string }; Body: CreateReplicationContract }>(
    "/v1/workspaces/:workspaceId/replication-contracts",
    {
      schema: {
        params: WorkspaceParamsSchema,
        body: CreateReplicationContractSchema,
        security: [{ oidcBearer: [] }],
      },
    },
    async (request, reply) => {
      const context = await authorize(request, request.params.workspaceId, "contract:write");
      const contract = await store.createReplicationContract(
        request.params.workspaceId,
        request.body,
        context.identity.subject,
      );
      return reply.status(201).send(contract);
    },
  );

  app.post<{
    Params: { workspaceId: string; source: string };
    Body: ChangeReplicationSourceState;
  }>(
    "/v1/workspaces/:workspaceId/replication-sources/:source/state",
    {
      schema: {
        params: SourceParamsSchema,
        body: ChangeReplicationSourceStateSchema,
        security: [{ oidcBearer: [] }],
      },
    },
    async (request) => {
      const context = await authorize(request, request.params.workspaceId, "source:control");
      return store.changeReplicationSourceState(
        request.params.workspaceId,
        request.params.source,
        request.body,
        context.identity.subject,
      );
    },
  );

  app.get<{ Params: { workspaceId: string; batchId: string } }>(
    "/v1/workspaces/:workspaceId/backup-batches/:batchId",
    { schema: { params: BatchParamsSchema, security: [{ oidcBearer: [] }] } },
    async (request) => {
      await authorize(request, request.params.workspaceId, "workspace:read");
      return store.getBackupBatch(request.params.workspaceId, request.params.batchId);
    },
  );

  app.get<{ Params: { workspaceId: string; batchId: string } }>(
    "/v1/workspaces/:workspaceId/backup-batches/:batchId/vault-verification",
    { schema: { params: BatchParamsSchema, security: [{ oidcBearer: [] }] } },
    async (request) => {
      await authorize(request, request.params.workspaceId, "backup:verify");
      return store.verifyVaultObject(request.params.workspaceId, request.params.batchId);
    },
  );

  app.post<{
    Params: { workspaceId: string; batchId: string };
    Body: CreateProjection;
  }>(
    "/v1/workspaces/:workspaceId/backup-batches/:batchId/projections",
    {
      schema: {
        params: BatchParamsSchema,
        body: CreateProjectionSchema,
        security: [{ oidcBearer: [] }],
      },
    },
    async (request, reply) => {
      const context = await authorize(request, request.params.workspaceId, "projection:write");
      const projection = await store.createProjection(
        request.params.workspaceId,
        request.params.batchId,
        request.body,
        context.identity.subject,
      );
      return reply.status(201).send(projection);
    },
  );

  app.get<{ Params: { workspaceId: string; projectionId: string } }>(
    "/v1/workspaces/:workspaceId/projections/:projectionId",
    { schema: { params: ProjectionParamsSchema, security: [{ oidcBearer: [] }] } },
    async (request) => {
      await authorize(request, request.params.workspaceId, "workspace:read");
      return store.getProjection(request.params.workspaceId, request.params.projectionId);
    },
  );

  app.post<{ Params: { workspaceId: string }; Body: CreateAIResult }>(
    "/v1/workspaces/:workspaceId/ai-results",
    {
      schema: {
        params: WorkspaceParamsSchema,
        body: CreateAIResultSchema,
        security: [{ oidcBearer: [] }],
      },
    },
    async (request, reply) => {
      const context = await authorize(request, request.params.workspaceId, "ai-result:write");
      const result = await store.createAIResult(
        request.params.workspaceId,
        request.body,
        context.identity.subject,
      );
      return reply.status(201).send(result);
    },
  );

  app.get<{ Params: { workspaceId: string; batchId: string } }>(
    "/v1/workspaces/:workspaceId/backup-batches/:batchId/restore-verification",
    { schema: { params: BatchParamsSchema, security: [{ oidcBearer: [] }] } },
    async (request) => {
      await authorize(request, request.params.workspaceId, "backup:verify");
      return store.verifyRestore(request.params.workspaceId, request.params.batchId);
    },
  );

  app.get<{ Params: { workspaceId: string; traceId: string } }>(
    "/v1/workspaces/:workspaceId/traces/:traceId",
    { schema: { params: TraceParamsSchema, security: [{ oidcBearer: [] }] } },
    async (request) => {
      await authorize(request, request.params.workspaceId, "audit:read");
      return store.getTrace(request.params.workspaceId, request.params.traceId);
    },
  );

  return app;
}
