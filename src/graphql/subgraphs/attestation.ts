import { createSchema as makeExecutableSchema } from 'graphql-yoga';

export const attestationSchema = makeExecutableSchema({
  typeDefs: `
    type Attestation {
      id: ID!
      businessId: String!
      period: String!
      attestedAt: String!
      status: String
      revokedAt: String
      revokeReason: String
    }

    type Query {
      _attestationDummy: String
    }
  `,
  resolvers: {
    Query: {
      _attestationDummy: () => 'dummy',
    },
  },
});
