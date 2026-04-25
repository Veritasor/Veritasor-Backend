# Test Setup Guide

## Installation

Install test dependencies:

```bash
npm install
```

This will install:
- `jest` - Test framework
- `@jest/globals` - Jest globals for TypeScript
- `ts-jest` - TypeScript preprocessor for Jest
- `supertest` - HTTP testing library
- `@types/jest` - TypeScript types for Jest
- `@types/supertest` - TypeScript types for Supertest

## Running Tests

```bash
# Run all tests once
npm test

# Run tests in watch mode (re-runs on file changes)
npm run test:watch

# Run tests with coverage report
npm run test:coverage
```

## Test Output

When you run `npm test`, you'll see output like:

```
PASS  tests/integration/auth.test.ts
  POST /api/auth/signup
    ✓ should create a new user with valid data (45ms)
    ✓ should return 400 when missing required fields (12ms)
    ✓ should return 409 when email already exists (18ms)
  POST /api/auth/login
    ✓ should login with valid credentials (23ms)
    ✓ should return 401 with invalid password (15ms)
    ...

Test Suites: 1 passed, 1 total
Tests:       25 passed, 25 total
```

## Coverage Report

Run `npm run test:coverage` to generate a coverage report:

```
----------------------|---------|----------|---------|---------|
File                  | % Stmts | % Branch | % Funcs | % Lines |
----------------------|---------|----------|---------|---------|
All files             |   85.23 |    78.45 |   90.12 |   84.67 |
 routes/              |   92.15 |    85.33 |   95.00 |   91.88 |
  auth.ts             |   92.15 |    85.33 |   95.00 |   91.88 |
----------------------|---------|----------|---------|---------|
```

Coverage reports are saved to the `coverage/` directory.

## Troubleshooting

### ESM Module Issues

If you encounter module resolution errors, ensure:
1. `"type": "module"` is in package.json
2. Import statements use `.js` extensions
3. Jest config has proper ESM settings

### TypeScript Errors

If TypeScript compilation fails:
1. Check `tsconfig.json` includes the `tests` directory
2. Ensure all type definitions are installed
3. Run `npm install` to update dependencies

### Port Already in Use

Tests create an Express app but don't bind to a port (supertest handles this internally), so port conflicts shouldn't occur.

## Next Steps

Once the actual auth routes are implemented:

1. Remove the `createMockAuthRouter()` function from `auth.test.ts`
2. Import the real auth router: `import { authRouter } from '../../src/routes/auth.js'`
3. Update the test setup: `app.use('/api/auth', authRouter)`
4. Run tests to verify the implementation matches the expected behavior
5. Add database setup/teardown if using a real database

## Writing New Tests

Follow this pattern for new integration tests:

```typescript
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals'
import request from 'supertest'
import express from 'express'

describe('Feature Name', () => {
  let app: express.Express

  beforeAll(() => {
    // Setup test app
  })

  it('should do something', async () => {
    const response = await request(app)
      .get('/api/endpoint')
      .expect(200)

    expect(response.body).toHaveProperty('data')
  })
})
```

## E2E Environment Setup

End-to-End (E2E) tests require a full system environment. Follow these steps to set up the necessary components:

### Prerequisites
- **Docker**: Used for running PostgreSQL and Stellar Quickstart.
- **Stellar Quickstart**: Provides a local Soroban RPC node.

### Local Infrastructure Setup

1. **Start PostgreSQL**:
   ```bash
   docker run --name veritasor-db -e POSTGRES_PASSWORD=password -p 5432:5432 -d postgres
   ```

2. **Start Stellar Quickstart (Soroban)**:
   ```bash
   docker run --rm -it \
     -p 8000:8000 \
     --name stellar \
     stellar/quickstart:latest \
     --testnet \
     --rpc
   ```

### Configuration

Create a `.env.test.e2e` file with the following:

```env
DATABASE_URL=postgresql://postgres:password@localhost:5432/postgres
SOROBAN_RPC_URL=http://localhost:8000/soroban/rpc
SOROBAN_NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
SOROBAN_CONTRACT_ID=C... (your test contract)
```

### Running E2E Tests

Run the E2E-specific suite:

```bash
# Set env and run vitest
DOTENV_CONFIG_PATH=.env.test.e2e npm run test:e2e
```

## Continuous Integration (CI)

Our CI pipeline enforces a **95% test coverage** threshold for all new contributions. Ensure that your PR includes both integration and E2E tests to meet this requirement.

Run coverage locally before pushing:
```bash
npm run test:coverage
```
