# Migration lock / statement timeout guard

Long-running DDL can hold locks and stall application traffic. The migration
runner in `src/db/migrate.ts` therefore sets **`lock_timeout`** and
**`statement_timeout`** for every up/down migration transaction and **fails
fast** when either limit is breached.

## Defaults

| Setting | Env var | Default |
|---|---|---|
| Lock wait | `MIGRATION_LOCK_TIMEOUT_MS` | `5000` (5s) |
| Statement | `MIGRATION_STATEMENT_TIMEOUT_MS` | `60000` (60s) |

Both are applied with `SET LOCAL` inside the migration transaction so they do
not leak to other sessions (including via PgBouncer transaction pooling).

`0` disables the corresponding timeout (PostgreSQL semantics).

## Fail-fast + audit

On breach the runner:

1. `ROLLBACK`s the migration transaction (nothing is recorded in `schema_migrations`).
2. Emits a structured audit event `migration_timeout_breach` via `logger.error`
   (or an injected `onAudit` sink in tests / automation).
3. Throws `MigrationTimeoutError` (`code: MIGRATION_TIMEOUT`) with
   `breach: 'lock_timeout' | 'statement_timeout'`.

PostgreSQL codes mapped:

| PG code | Meaning | Breach |
|---|---|---|
| `55P03` | `lock_not_available` | `lock_timeout` |
| `57014` | `query_canceled` (statement timeout) | `statement_timeout` |

Audit payload fields: `event`, `version`, `direction` (`up`|`down`), `breach`,
`lockTimeoutMs`, `statementTimeoutMs`, optional `pgCode`, `message`, `timestamp`.

## Per-migration overrides

Place directives in **leading** SQL comments (before the first non-comment line):

```sql
-- @lock_timeout_ms 5000
-- @statement_timeout_ms 0
CREATE INDEX idx_events_created_at ON events (created_at);
```

Alternate forms accepted: `@lock_timeout 5s`, `@statement_timeout: 10m`.
Bare integers are milliseconds; suffixes `ms` / `s` / `m` are supported.

### Long index builds

Index builds that need more than the default statement budget should raise or
disable `statement_timeout` while keeping a tight `lock_timeout` so lock waits
still fail fast:

```sql
-- @lock_timeout_ms 5000
-- @statement_timeout_ms 0
CREATE INDEX idx_big ON large_table (col);
```

> Note: `CREATE INDEX CONCURRENTLY` cannot run inside a transaction. This runner
> always wraps migrations in `BEGIN`/`COMMIT`, so use a normal `CREATE INDEX`
> with an elevated `statement_timeout` instead.

## Security notes

- Timeout values are validated as non-negative integers within
  `[0, 86400000]` before interpolation into `SET LOCAL`. Raw strings from SQL
  headers or env are never concatenated into SQL.
- Unrelated SQL errors still roll back and do **not** emit a timeout audit event.
- Defaults favour short lock waits so a blocked migration cannot hold the
  deploy pipeline / connection while traffic queues behind an AccessExclusiveLock.

## Run-level options (programmatic)

```ts
await runMigrations(client, migrationsDir, {
  timeouts: { lockTimeoutMs: 1500, statementTimeoutMs: 45_000 },
  onAudit: (record) => mySink(record),
})
```

File-level directives override run-level / env values for that migration only.

## Testing

```bash
npx vitest run tests/db/migrate.test.ts
```

Coverage includes default application order (`BEGIN` → `SET LOCAL` → DDL),
lock/statement breach fail-fast + audit, long-index override (`statement_timeout=0`),
rollback path parity, and rejection of unsafe override values.
