import pg from 'pg';

export type Pool = pg.Pool;
export type Client = pg.PoolClient;
/** Anything that can run a query: the pool or a client inside a transaction. */
export interface Queryable {
  query: pg.Pool['query'];
}

export function createPool(connectionString: string, options: { schema?: string } = {}): Pool {
  const pool = new pg.Pool({
    connectionString,
    max: 10,
    // A search_path per pool lets two services share one database server in tests and in the demo.
    ...(options.schema ? { options: `-c search_path=${options.schema}` } : {}),
  });
  pool.on('error', () => undefined); // an idle client dying must not take the process down; the next query reconnects
  return pool;
}

export async function transaction<T>(pool: Pool, work: (client: Client) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

const SCHEMA = `
-- The audit chain. seq is assigned under a row lock as "previous + 1", not by a sequence: a sequence skips numbers on
-- rollback, and here a missing number is evidence.
CREATE TABLE IF NOT EXISTS audit_chain (
  seq        bigint      PRIMARY KEY,
  id         uuid        NOT NULL UNIQUE,
  at         timestamptz NOT NULL,
  actor      text        NOT NULL,
  action     text        NOT NULL,
  subject    text,
  ip         text,
  user_agent text,
  metadata   jsonb       NOT NULL DEFAULT '{}',
  prev_hash  text        NOT NULL,
  row_hash   text        NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_chain_action_at_idx ON audit_chain (action, at);
CREATE INDEX IF NOT EXISTS audit_chain_ip_idx ON audit_chain (ip, at) WHERE ip IS NOT NULL;

-- One row: where the chain ends. Appends lock it, which is what serialises writers; verification compares it with
-- what is actually in the table, which is what notices a truncated tail.
CREATE TABLE IF NOT EXISTS chain_head (
  id        int    PRIMARY KEY CHECK (id = 1),
  last_seq  bigint NOT NULL,
  last_hash text   NOT NULL
);

-- An operator's "this was benign". It never edits the audit row; it only changes how the risk score counts it.
CREATE TABLE IF NOT EXISTS overrides (
  id         bigserial   PRIMARY KEY,
  audit_seq  bigint      NOT NULL REFERENCES audit_chain (seq),
  action     text        NOT NULL,
  reason     text        NOT NULL,
  operator   text        NOT NULL,
  status     text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS overrides_one_active_idx ON overrides (audit_seq) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS proposals (
  id          uuid        PRIMARY KEY,
  kind        text        NOT NULL CHECK (kind IN ('block_ip', 'suspend_subject', 'lockdown')),
  target      text        NOT NULL,
  rationale   text        NOT NULL,
  evidence    jsonb       NOT NULL DEFAULT '[]',
  severity    text        NOT NULL,
  source      text        NOT NULL,
  status      text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'executed', 'rejected', 'failed')),
  created_at  timestamptz NOT NULL,
  decided_at  timestamptz,
  decided_by  text,
  decision_note text
);
-- The same proposal is not queued twice while it waits for a decision.
CREATE UNIQUE INDEX IF NOT EXISTS proposals_one_pending_idx ON proposals (kind, target) WHERE status = 'pending';
`;

/** Idempotent: safe to run on every boot. A migration tool earns its keep once there is a second migration. */
export async function migrate(pool: Pool): Promise<void> {
  await pool.query(SCHEMA);
  await pool.query("INSERT INTO chain_head (id, last_seq, last_hash) VALUES (1, 0, '') ON CONFLICT (id) DO NOTHING");
}
