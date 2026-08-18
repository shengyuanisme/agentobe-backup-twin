import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { loadConfig } from "../config.js";
import { createPool } from "./pool.js";

export async function migrate(connectionString = loadConfig().databaseUrl): Promise<void> {
  const pool = createPool(connectionString);
  const migrationClient = await pool.connect();
  try {
    const migrationsDirectory = fileURLToPath(new URL("./migrations/", import.meta.url));
    await migrationClient.query("SELECT pg_advisory_lock(190520260818)");
    await migrationClient.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      name text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )`);
    const files = (await readdir(migrationsDirectory))
      .filter((name) => name.endsWith(".sql"))
      .sort();
    for (const name of files) {
      const applied = await migrationClient.query(
        "SELECT 1 FROM schema_migrations WHERE name = $1",
        [name],
      );
      if (applied.rowCount) continue;
      const sql = await readFile(`${migrationsDirectory}/${name}`, "utf8");
      try {
        await migrationClient.query("BEGIN");
        await migrationClient.query(sql);
        await migrationClient.query("INSERT INTO schema_migrations (name) VALUES ($1)", [name]);
        await migrationClient.query("COMMIT");
      } catch (error) {
        await migrationClient.query("ROLLBACK");
        throw error;
      }
    }
  } finally {
    await migrationClient.query("SELECT pg_advisory_unlock(190520260818)").catch(() => undefined);
    migrationClient.release();
    await pool.end();
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  await migrate();
  console.log("Database migration complete.");
}
