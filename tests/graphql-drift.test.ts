/**
 * GraphQL Schema Drift Check
 *
 * Invoked by .github/workflows/schema-drift.yml on PRs that touch
 * src/graphql/** or src/routes/admin.graphql.ts.
 */
import { describe, it, expect } from 'vitest';
import { printSchemaWithDirectives } from '@graphql-tools/utils';
import { attestationSchema } from '../src/graphql/subgraphs/attestation.js';
import { businessSchema } from '../src/graphql/subgraphs/business.js';
import { userSchema } from '../src/graphql/subgraphs/user.js';
import { gatewaySchema } from '../src/graphql/gateway.js';

const schemas: Record<string, any> = {
  attestation: attestationSchema,
  business: businessSchema,
  user: userSchema,
  gateway: gatewaySchema,
};

function sdl(schema: any): string {
  return printSchemaWithDirectives(schema);
}

describe('GraphQL schema drift', () => {
  it.each(Object.keys(schemas))('%s schema SDL matches snapshot', (name) => {
    expect(sdl(schemas[name])).toMatchSnapshot();
  });

  it('gateway exposes root Query fields', () => {
    const gatewayFields = Object.keys(gatewaySchema.getQueryType()?.getFields() ?? {});
    expect(gatewayFields.length).toBeGreaterThan(0);
  });
});
