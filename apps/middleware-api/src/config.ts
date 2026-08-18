export interface AppConfig {
  host: string;
  port: number;
  databaseUrl: string;
  projectionTokenKey: string;
  logLevel: string;
  consoleOrigins: string[];
  auth: {
    issuer: string;
    audience: string;
    jwksUri?: string;
    algorithms: string[];
    bootstrap?: {
      organizationId: string;
      subject: string;
      email?: string;
      displayName?: string;
    };
  };
  vault: {
    driver: "file" | "spaces";
    masterKey: string;
    keyVersion: string;
    fileDirectory: string;
    spaces?: {
      bucket: string;
      region: string;
      accessKeyId: string;
      secretAccessKey: string;
    };
  };
  outbox: {
    pollIntervalMs: number;
    webhookUrl?: string;
  };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const vaultDriver = env.VAULT_DRIVER === "spaces" ? "spaces" : "file";
  const spaces = vaultDriver === "spaces"
    ? {
        bucket: required(env, "SPACES_BUCKET"),
        region: required(env, "SPACES_REGION"),
        accessKeyId: required(env, "SPACES_ACCESS_KEY_ID"),
        secretAccessKey: required(env, "SPACES_SECRET_ACCESS_KEY"),
      }
    : undefined;
  const issuer = env.OIDC_ISSUER ?? "http://localhost:8080/realms/agentobe";
  const bootstrap = env.AUTH_BOOTSTRAP_ORGANIZATION_ID && env.AUTH_BOOTSTRAP_SUBJECT
    ? {
        organizationId: env.AUTH_BOOTSTRAP_ORGANIZATION_ID,
        subject: env.AUTH_BOOTSTRAP_SUBJECT,
        ...(env.AUTH_BOOTSTRAP_EMAIL ? { email: env.AUTH_BOOTSTRAP_EMAIL } : {}),
        ...(env.AUTH_BOOTSTRAP_DISPLAY_NAME
          ? { displayName: env.AUTH_BOOTSTRAP_DISPLAY_NAME }
          : {}),
      }
    : undefined;
  return {
    host: env.HOST ?? "127.0.0.1",
    port: Number(env.PORT ?? "4100"),
    databaseUrl:
      env.DATABASE_URL ??
      "postgres://agentobe:agentobe-local@127.0.0.1:54329/agentobe",
    projectionTokenKey:
      env.PROJECTION_TOKEN_KEY ?? "agentobe-demo-projection-token-key",
    logLevel: env.LOG_LEVEL ?? "info",
    consoleOrigins: (env.CONSOLE_ORIGINS ?? "http://localhost:4173,http://localhost:5173")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
    auth: {
      issuer,
      audience: env.OIDC_AUDIENCE ?? "agentobe-api",
      ...(env.OIDC_JWKS_URI ? { jwksUri: env.OIDC_JWKS_URI } : {}),
      algorithms: (env.OIDC_ALLOWED_ALGORITHMS ?? "RS256")
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean),
      ...(bootstrap ? { bootstrap } : {}),
    },
    vault: {
      driver: vaultDriver,
      masterKey:
        env.VAULT_MASTER_KEY ?? "YWdlbnRvYmUtZGVtby12YXVsdC1rZXktMDAwMDAwMDA=",
      keyVersion: env.VAULT_KEY_VERSION ?? "demo-v1",
      fileDirectory: env.VAULT_FILE_DIR ?? "/tmp/agentobe-vault",
      ...(spaces ? { spaces } : {}),
    },
    outbox: {
      pollIntervalMs: Number(env.OUTBOX_POLL_INTERVAL_MS ?? "1000"),
      ...(env.OUTBOX_WEBHOOK_URL ? { webhookUrl: env.OUTBOX_WEBHOOK_URL } : {}),
    },
  };
}

function required(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key];
  if (!value) throw new Error(`${key} is required for the selected runtime configuration.`);
  return value;
}
