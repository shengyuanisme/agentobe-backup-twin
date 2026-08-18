import { loadConfig } from "./config.js";
import { migrate } from "./db/migrate.js";
import { createPool } from "./db/pool.js";
import { buildServer } from "./server.js";
import {
  EncryptedSourceVault,
  FileBlobStore,
  SpacesBlobStore,
} from "./vault.js";
import { AuthorizationService, OidcAccessTokenVerifier } from "./auth.js";

const config = loadConfig();
await migrate(config.databaseUrl);
const pool = createPool(config.databaseUrl);
const tokenVerifier = await OidcAccessTokenVerifier.create(config.auth);
const authorization = new AuthorizationService(pool, tokenVerifier);
if (config.auth.bootstrap) {
  await authorization.ensureBootstrapOwner({
    ...config.auth.bootstrap,
    issuer: config.auth.issuer,
  });
}
const blobStore = config.vault.driver === "spaces"
  ? new SpacesBlobStore(
      config.vault.spaces!.bucket,
      config.vault.spaces!.region,
      config.vault.spaces!.accessKeyId,
      config.vault.spaces!.secretAccessKey,
    )
  : new FileBlobStore(config.vault.fileDirectory);
const sourceVault = new EncryptedSourceVault(
  blobStore,
  config.vault.masterKey,
  config.vault.keyVersion,
);
const app = await buildServer({
  pool,
  projectionTokenKey: config.projectionTokenKey,
  sourceVault,
  tokenVerifier,
  consoleOrigins: config.consoleOrigins,
  logLevel: config.logLevel,
});

const shutdown = async () => {
  await app.close();
  await pool.end();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

await app.listen({ host: config.host, port: config.port });
