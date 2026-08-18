import { setTimeout as delay } from "node:timers/promises";
import { loadConfig } from "./config.js";
import { createPool } from "./db/pool.js";
import { migrate } from "./db/migrate.js";
import {
  drainOutboxOnce,
  StructuredLogPublisher,
  WebhookPublisher,
} from "./outbox-worker.js";

const config = loadConfig();
await migrate(config.databaseUrl);
const pool = createPool(config.databaseUrl);
const publisher = config.outbox.webhookUrl
  ? new WebhookPublisher(config.outbox.webhookUrl)
  : new StructuredLogPublisher();
let stopping = false;
process.on("SIGINT", () => { stopping = true; });
process.on("SIGTERM", () => { stopping = true; });

while (!stopping) {
  const result = await drainOutboxOnce(pool, publisher);
  if (result.published === 0 && result.failed === 0) {
    await delay(config.outbox.pollIntervalMs);
  }
}
await pool.end();
