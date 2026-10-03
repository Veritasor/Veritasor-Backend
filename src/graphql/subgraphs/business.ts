import { createSchema as makeExecutableSchema } from 'graphql-yoga';
import * as businessRepository from '../../repositories/business.js';

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
      business: async (_: unknown, { id }: { id: string }) => businessRepository.getById(id),
    },
  },
});
