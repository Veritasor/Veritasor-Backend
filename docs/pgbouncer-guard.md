# PgBouncer Transaction-Mode Guard

## Overview
The PgBouncer guard detects transaction pooling mode and automatically disables named prepared statements to prevent silent failures.

## Problem Statement

### PgBouncer Transaction Mode
- PgBouncer in transaction mode reuses connections across sessions
- Server-side prepared statements are session-bound
- When a connection is reused, the prepared statement may not exist
- This causes silent failures or "prepared statement does not exist" errors

### Solution
- Detect PgBouncer mode at connection time
- Disable named prepared statements when in transaction mode
- Log warnings with recommendations
- Provide fallback to unnamed prepared statements

## Detection Methods

### 1. Environment Variable
```bash
PGBOUNCER_MODE=transaction  # or session, statement
interface ClientOptions {
  disablePreparedStatements?: boolean;  // Force disable
  pgbouncerMode?: 'session' | 'transaction' | 'statement';  // Override
}
import { getPgClient } from './db/client';

const client = getPgClient();

// This will automatically use safe query methods
const result = await client.query('SELECT * FROM users WHERE id = $1', [userId]);
const client = new PgClient({
  disablePreparedStatements: true,
});
const client = new PgClient({
  pgbouncerMode: 'transaction',
});
