const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "")
  ?? "/api";
let accessToken: string | undefined;
let workspaceId: string | undefined;

export function configureApi(token: string, selectedWorkspaceId?: string) {
  accessToken = token;
  workspaceId = selectedWorkspaceId;
}

function workspace(): string {
  if (!workspaceId) throw new Error("No authorized workspace is selected.");
  return workspaceId;
}

export interface WorkspaceAccess {
  organizationId: string;
  organizationName: string;
  workspaceId: string;
  workspaceName: string;
  roles: Array<"owner" | "admin" | "operator" | "auditor" | "runner" | "viewer">;
  permissions: string[];
}

export interface MeResponse {
  identity: { issuer: string; subject: string; email?: string; displayName?: string };
  workspaces: WorkspaceAccess[];
}

export interface ReplicationSource {
  source: string;
  status: "active" | "paused";
  reason: string;
  version: string | number;
  updated_by: string;
  updated_at: string;
  contract_count: number;
  latest_contract_at: string;
}

export interface ReplicationContract {
  id: string;
  source: string;
  version: string;
  rules: { allow: string[]; tokenize: string[]; deny: string[]; simulation_use: string[] };
  freshness_slo_seconds: number;
  retention_days: number;
  created_by: string;
  created_at: string;
}

export interface BackupBatch {
  id: string;
  traceId: string;
  source: string;
  contractVersion: string;
  schemaVersion: string;
  cursor: { start: string; end: string };
  status: "sealed" | "degraded" | "failed";
  manifestHash: string;
  recordCount: number;
  classifications: string[];
  sealedAt: string;
}

export interface Projection {
  id: string;
  backupBatchId: string;
  traceId: string;
  missionId: string;
  runnerId: string;
  version: number;
  status: "sealed" | "revoked";
  projectionHash: string;
  payload: { tickets: Array<Record<string, unknown>> };
  createdAt: string;
}

export interface SimulationMetrics {
  slaBreachRate: number;
  averageQueueAgeHours: number;
  escalationRate: number;
  openWorkload: number;
}

export interface SimulationBranch {
  id: string;
  name: string;
  strategy: string;
  ordinal: number;
  status: "completed" | "inconclusive" | "failed";
  confidence: number;
  assumptions: string[];
  blindSpots: string[];
  metrics: SimulationMetrics;
  delta: SimulationMetrics;
  steps: Array<{ sequence: number; tool: string; summary: string; target?: string; before?: unknown; after?: unknown; stateHash: string }>;
  stateHash: string;
  reproducible: boolean;
}

export interface SimulationExperiment {
  id: string;
  attempt: number;
  status: string;
  requestedBranches: number;
  agentVersion: string;
  toolVersion: string;
  inputHash: string;
  summary: { branchCount: number; completedBranches: number; reproducibleBranches: number; productionSideEffects: number };
  startedAt: string;
  completedAt: string;
  branches: SimulationBranch[];
}

export interface SimulationMission {
  id: string;
  projectionId: string;
  backupBatchId: string;
  traceId: string;
  name: string;
  objective: string;
  successMetric: string;
  guardMetric: string;
  constraints: { prohibitTicketClosure: boolean; prohibitExternalMessages: boolean; maxP1AgeHours: number; queueCapacity: Record<string, number> };
  budget: { maxBranches: number; maxStepsPerBranch: number; maxRuntimeSeconds: number };
  toolScope: string[];
  ownerId: string;
  runnerId: string;
  status: "ready" | "running" | "paused" | "completed" | "cancelled" | "blocked";
  createdAt: string;
  experiments?: SimulationExperiment[];
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  if (!accessToken) throw new Error("Authentication is required.");
  const headers: Record<string, string> = { authorization: `Bearer ${accessToken}` };
  if (init?.body) headers["content-type"] = "application/json";
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      ...headers,
      ...init?.headers,
    },
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body?.error?.message ?? `HTTP ${response.status}`);
  return body as T;
}

export const api = {
  me: () => request<MeResponse>("/v1/me"),
  seed: () => request<{ batch: BackupBatch }>("/v1/demo/seed", { method: "POST" }),
  sources: () => request<{ items: ReplicationSource[] }>(
    `/v1/workspaces/${workspace()}/replication-sources`,
  ),
  contracts: () => request<{ items: ReplicationContract[] }>(
    `/v1/workspaces/${workspace()}/replication-contracts`,
  ),
  createContract: (input: {
    source: string;
    version: string;
    rules: {
      entity: "ticket";
      mode: "snapshot_plus_events";
      allow: string[];
      tokenize: string[];
      deny: string[];
      simulation_use: string[];
    };
    freshnessSloSeconds: number;
    retentionDays: number;
  }) => request<ReplicationContract>(
    `/v1/workspaces/${workspace()}/replication-contracts`,
    { method: "POST", body: JSON.stringify(input) },
  ),
  batches: () => request<{ items: BackupBatch[] }>(
    `/v1/workspaces/${workspace()}/backup-batches`,
  ),
  changeSourceState: (source: string, status: "active" | "paused", reason: string) =>
    request<ReplicationSource>(
      `/v1/workspaces/${workspace()}/replication-sources/${encodeURIComponent(source)}/state`,
      { method: "POST", body: JSON.stringify({ status, reason }) },
    ),
  verifyVault: (batchId: string) => request<{
    verification: { status: string; encryptionAlgorithm: string; keyVersion: string };
    object: { storageDriver: string; sizeBytes: number; ciphertextHash: string };
  }>(`/v1/workspaces/${workspace()}/backup-batches/${batchId}/vault-verification`),
  verifyRestore: (batchId: string) => request<{
    status: string;
    recordCount: number;
    restoredStateHash: string;
  }>(`/v1/workspaces/${workspace()}/backup-batches/${batchId}/restore-verification`),
  createProjection: (batchId: string) => request<{ id: string; projectionHash: string }>(
    `/v1/workspaces/${workspace()}/backup-batches/${batchId}/projections`,
    {
      method: "POST",
      body: JSON.stringify({
        missionId: `console-inspection-${Date.now()}`,
        runnerId: "shadow-runner-demo",
        contractVersion: "v1",
      }),
    },
  ),
  projections: () => request<{ items: Projection[] }>(
    `/v1/workspaces/${workspace()}/projections`,
  ),
  missions: () => request<{ items: SimulationMission[] }>(
    `/v1/workspaces/${workspace()}/simulation-missions`,
  ),
  mission: (missionId: string) => request<SimulationMission>(
    `/v1/workspaces/${workspace()}/simulation-missions/${missionId}`,
  ),
  createMission: (input: {
    name: string;
    objective: string;
    projectionId: string;
    successMetric: "sla_breach_rate";
    guardMetric: "escalation_rate";
    constraints: { prohibitTicketClosure: true; prohibitExternalMessages: true; maxP1AgeHours: number; queueCapacity: Record<string, number> };
    budget: { maxBranches: number; maxStepsPerBranch: number; maxRuntimeSeconds: number };
    toolScope: Array<"ticket.priority" | "ticket.queue" | "ticket.capacity">;
  }) => request<SimulationMission>(
    `/v1/workspaces/${workspace()}/simulation-missions`,
    { method: "POST", body: JSON.stringify(input) },
  ),
  runMission: (missionId: string, requestedBranches = 4) => request<SimulationMission>(
    `/v1/workspaces/${workspace()}/simulation-missions/${missionId}/run`,
    { method: "POST", body: JSON.stringify({ requestedBranches }) },
  ),
};
