# Migration rollback verification

Down migrations (`*.down.sql`) exist so a bad deploy can be reversed, but
nothing exercised them — a broken or missing `down.sql` was only discovered
during an actual incident. `src/db/migrate.ts` now has a **dry-run rollback
verifier** that applies and rolls back each migration against a disposable
scratch database and reports whether the rollback was clean.

## What it checks

For each target migration `verifyMigrationRollback()`:

1. Snapshots the schema (`captureSchemaSnapshot`) before touching anything.
2. Applies `up.sql`.
3. Applies `down.sql`.
4. Snapshots the schema again and diffs it against the pre-up snapshot
   (`diffSchemaSnapshots`). Any difference — a leftover column/table/index,
   or something the rollback over-dropped — is **schema drift** and fails
   the check.
5. Re-applies `up.sql` so the scratch database ends up fully migrated,
   matching what a real deploy leaves behind and what the *next* migration
   in the sequence expects to build on.

The schema snapshot is structural only (`information_schema.columns`,
`pg_indexes`, `information_schema.table_constraints` for the `public`
schema, excluding `schema_migrations` itself) — it is a DDL/shape check,
not a data check.

`runRollbackVerification()` runs this for a set of target versions. Any
earlier migration *not* in the target set is applied (but not verified) so
later migrations see the schema they depend on — this lets CI verify only
the migrations a PR actually touches without needing to re-verify the
entire history on every run.

## Non-transactional DDL

Some statements (`CREATE/DROP INDEX CONCURRENTLY`, `REINDEX CONCURRENTLY`,
`ALTER TYPE ... ADD VALUE`, `VACUUM`, `CREATE/DROP DATABASE`, `ALTER
SYSTEM`, `CLUSTER`) cannot run inside `BEGIN`/`COMMIT` in PostgreSQL.
`requiresAutocommit()` detects these by pattern-matching the migration SQL;
when present, the verifier runs the migration in autocommit mode instead of
wrapping it in a transaction. This means a failure partway through such a
migration **cannot be rolled back automatically** — the verifier reports it
(`phase: 'up' | 'down'`) rather than silently losing the failure, and since
verification only ever runs against a disposable scratch database, a
partially-applied migration there is safe to discard.

## Safety: scratch database only

`assertScratchDatabase()` refuses to run verification unless `DATABASE_URL`
looks disposable: a loopback host (`localhost` / `127.0.0.1` / `::1` — the
normal shape of a CI service container) or a database name containing
`test`, `scratch`, `ci`, or `ephemeral`. Verification repeatedly
applies/reverts DDL and can leave a database mid-migration on failure, so
this guard exists to prevent an accidental run against a real environment.
Set `MIGRATION_VERIFY_FORCE=true` to override it explicitly.

## Running it

```bash
# Verify every discovered migration
DATABASE_URL=postgres://scratch:scratch@localhost:5432/migration_verify_scratch \
  npm run migrate:verify-rollback

# Verify only specific migrations (comma-separated versions)
npm run migrate:verify-rollback -- --only=20260627_001_add_businesses_reminder_columns
```

Output is a Markdown report (pass/fail, timings, and mode per migration).
When run in GitHub Actions with `GITHUB_STEP_SUMMARY` set, the same report
is also appended there so it shows up on the PR's job summary. The process
exits non-zero if any migration failed verification.

## CI integration

`.github/workflows/migration-rollback-verify.yml` runs on every PR that
touches `src/db/migrations/**` or `src/db/migrate.ts`. It starts a
`postgres:16-alpine` service container, diffs `src/db/migrations` against
the PR's base branch to find which migration versions changed, and verifies
just those (falling back to verifying everything if `migrate.ts` itself
changed without a migration diff).

## Adding a new migration

`getDownSql()` already refuses `npm run migrate:rollback` when a
`*.down.sql` file is missing — the verifier adds the next layer: even when
a `down.sql` exists, CI now confirms it actually reverses the `up.sql`
cleanly before the PR merges.
