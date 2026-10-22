import { createYoga } from 'graphql-yoga';
import { createSchema as makeExecutableSchema } from 'graphql-yoga';
import { mapSchema, getDirective, MapperKind } from '@graphql-tools/utils';
import { defaultFieldResolver, GraphQLSchema, GraphQLError } from 'graphql';
import * as attestationRepository from '../repositories/attestationRepository.js';
import { db } from '../db/client.js';

function authDirective(directiveName: string) {
  return {
    authDirectiveTypeDefs: `directive @${directiveName}(role: String, requireTenancy: Boolean) on FIELD_DEFINITION`,
    authDirectiveTransformer: (schema: GraphQLSchema) =>
      mapSchema(schema, {
        [MapperKind.OBJECT_FIELD]: (fieldConfig) => {
          const authDirective = getDirective(schema, fieldConfig, directiveName)?.[0];
          if (authDirective) {
            const { resolve = defaultFieldResolver } = fieldConfig;
            fieldConfig.resolve = async function (source, args, context, info) {
              const user = (context as any).req?.user;
              
              if (authDirective.requireTenancy) {
                if (!user) {
                  return null; // Return null for unauthorized requests according to GraphQL best practices for partial data
                }
                if (source.businessId && user.userId !== source.businessId) {
                  return null;
                }
              }

              if (authDirective.role) {
                if (!user || user.role !== authDirective.role) {
                  return null;
                }
              }

              return resolve(source, args, context, info);
            };
            return fieldConfig;
          }
        },
      }),
  };
}

const { authDirectiveTypeDefs, authDirectiveTransformer } = authDirective('auth');

const typeDefs = `
  ${authDirectiveTypeDefs}

  type Attestation {
    id: ID!
    businessId: String @auth(requireTenancy: true)
    period: String!
    merkleRoot: String!
    txHash: String!
    status: String!
    attestedAt: String!
  }

  type Query {
    attestationByHash(hash: String!): Attestation
  }
`;

const resolvers = {
  Query: {
    attestationByHash: async (_: any, { hash }: { hash: string }) => {
      const attestation = await attestationRepository.getById(db, hash);
      if (!attestation) {
        return null;
      }
      return {
        id: attestation.id,
        businessId: attestation.businessId,
        period: attestation.period,
        merkleRoot: attestation.merkleRoot,
        txHash: attestation.txHash,
        status: attestation.status,
        attestedAt: attestation.createdAt.toISOString(),
      };
    },
  },
};

let schema = makeExecutableSchema({
  typeDefs,
  resolvers,
});

schema = authDirectiveTransformer(schema);

export const publicGraphqlYoga = createYoga({
  schema,
  graphqlEndpoint: '/api/v1/public/attestations/graphql',
});
