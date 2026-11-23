import { createSchema as makeExecutableSchema } from 'graphql-yoga';
import * as businessRepository from '../../repositories/business.js';

interface BusinessLoaderContext {
  loaders: {
    businessLoader: {
      load(id: string): Promise<businessRepository.Business | null>;
    };
  };
}

export const businessSchema = makeExecutableSchema({
  typeDefs: `
    type Business {
      id: ID!
      userId: String!
      name: String!
      email: String!
      industry: String
      description: String
      website: String
      reportingPeriod: String!
      reportingTimezone: String!
      lastReminderSentAt: String
      createdAt: String!
      updatedAt: String!
    }

    type Query {
      businesses: [Business!]!
      business(id: ID!): Business
    }
  `,
  resolvers: {
    Query: {
      businesses: async () => businessRepository.getAll(),
      business: async (
        _: unknown,
        { id }: { id: string },
        context: BusinessLoaderContext,
      ) => context.loaders.businessLoader.load(id),
    },
  },
});
