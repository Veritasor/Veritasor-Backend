import { GraphQLObjectType, graphql } from 'graphql';
import { describe, expect, it } from 'vitest';
import { attestationSchema } from './attestation.js';

describe('attestationSchema', () => {
  it('resolves the dummy query', async () => {
    const result = await graphql({
      schema: attestationSchema,
      source: '{ _attestationDummy }',
    });

    expect(result.errors).toBeUndefined();
    expect(result.data).toEqual({ _attestationDummy: 'dummy' });
  });

  it('declares the attestation contract and optional lifecycle fields', () => {
    const attestationType = attestationSchema.getType('Attestation');

    expect(attestationType).toBeInstanceOf(GraphQLObjectType);
    const fields = (attestationType as GraphQLObjectType).getFields();
    expect(Object.fromEntries(
      Object.entries(fields).map(([name, field]) => [name, field.type.toString()]),
    )).toEqual({
      id: 'ID!',
      businessId: 'String!',
      period: 'String!',
      attestedAt: 'String!',
      status: 'String',
      revokedAt: 'String',
      revokeReason: 'String',
    });
  });

  it('rejects unknown fields and arguments deterministically', async () => {
    const unknownField = await graphql({
      schema: attestationSchema,
      source: '{ unknownAttestation }',
    });
    const unknownArgument = await graphql({
      schema: attestationSchema,
      source: '{ _attestationDummy(unexpected: "value") }',
    });

    expect(unknownField.errors?.map(error => error.message)).toEqual([
      'Cannot query field "unknownAttestation" on type "Query".',
    ]);
    expect(unknownArgument.errors?.map(error => error.message)).toEqual([
      'Unknown argument "unexpected" on field "Query._attestationDummy".',
    ]);
    expect(unknownField.data).toBeUndefined();
    expect(unknownArgument.data).toBeUndefined();
  });

  it('has no mutation root or state transitions', () => {
    expect(attestationSchema.getMutationType()).toBeUndefined();
  });
});