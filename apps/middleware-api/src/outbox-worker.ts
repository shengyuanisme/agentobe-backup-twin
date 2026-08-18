import type { Pool } from "pg";

export interface OutboxMessage {
  id: string;
  workspaceId: string;
  traceId: string;
  topic: string;
  payload: Record<string, unknown>;
  createdAt: Date;
  attempts: number;
}

export interface OutboxPublisher {
  publish(message: OutboxMessage): Promise<void>;
}

interface OutboxRow {
  id: string;
  workspace_id: string;
  trace_id: string;
  topic: string;
  payload: Record<string, unknown>;
  created_at: Date;
  attempts: number;
}

export async function drainOutboxOnce(
  pool: Pool,
  publisher: OutboxPublisher,
  limit = 25,
): Promise<{ published: number; failed: number }> {
  const client = await pool.connect();
  let published = 0;
  let failed = 0;
  try {
    await client.query("BEGIN");
    const result = await client.query<OutboxRow>(
      `SELECT id, workspace_id, trace_id, topic, payload, created_at, attempts
       FROM outbox_events
       WHERE published_at IS NULL AND next_attempt_at <= now()
       ORDER BY created_at
       FOR UPDATE SKIP LOCKED
       LIMIT $1`,
      [limit],
    );
    for (const row of result.rows) {
      const message: OutboxMessage = {
        id: row.id,
        workspaceId: row.workspace_id,
        traceId: row.trace_id,
        topic: row.topic,
        payload: row.payload,
        createdAt: row.created_at,
        attempts: row.attempts,
      };
      try {
        await publisher.publish(message);
        await client.query(
          "UPDATE outbox_events SET published_at = now(), attempts = attempts + 1, last_error = NULL WHERE id = $1",
          [row.id],
        );
        published += 1;
      } catch (error) {
        const delaySeconds = Math.min(300, 2 ** Math.min(8, row.attempts + 1));
        await client.query(
          `UPDATE outbox_events
           SET attempts = attempts + 1,
               last_error = $2,
               next_attempt_at = now() + ($3::text || ' seconds')::interval
           WHERE id = $1`,
          [
            row.id,
            error instanceof Error ? error.message.slice(0, 1000) : "Unknown publisher error",
            delaySeconds,
          ],
        );
        failed += 1;
      }
    }
    await client.query("COMMIT");
    return { published, failed };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export class WebhookPublisher implements OutboxPublisher {
  constructor(private readonly url: string) {}
  async publish(message: OutboxMessage): Promise<void> {
    const response = await fetch(this.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(message),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`Outbox webhook returned HTTP ${response.status}`);
  }
}

export class StructuredLogPublisher implements OutboxPublisher {
  async publish(message: OutboxMessage): Promise<void> {
    console.log(JSON.stringify({ type: "agentobe.outbox", ...message }));
  }
}
