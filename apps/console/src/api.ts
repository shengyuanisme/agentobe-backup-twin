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
};
