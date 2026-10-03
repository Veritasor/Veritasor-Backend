import { createSchema as makeExecutableSchema } from 'graphql-yoga';
import * as userRepository from '../../repositories/userRepository.js';
import * as auditLogRepository from '../../repositories/auditLogRepository.js';

export const userSchema = makeExecutableSchema({
  typeDefs: `
    scalar DateTime
    scalar JSON

    enum UserRole {
      user
      admin
      business_admin
    }

    type User {
      id: ID!
      email: String!
      role: UserRole!
      createdAt: DateTime!
      updatedAt: DateTime!
      auditLogs: [AuditLog!]
    }

    type AuditLog {
      id: ID!
      userId: String!
      action: String!
      resource: String!
      resourceId: String
      metadata: JSON
      timestamp: DateTime!
      actor: User
    }

    type Query {
      users: [User!]!
      user(id: ID!): User
      auditLogs: [AuditLog!]!
      auditLog(id: ID!): AuditLog
    }
  `,
  resolvers: {
    Query: {
      users: async () => userRepository.getAllUsers(),
      user: async (_: unknown, { id }: { id: string }) => userRepository.findUserById(id),
      auditLogs: async () => {
        const result = await auditLogRepository.queryAuditLogs({ limit: 100 });
        return result.data;
      },
      auditLog: async (_: unknown, { id }: { id: string }) => {
        const logs = await auditLogRepository.getAllAuditLogs();
        return logs.find(l => l.id === id) || null;
      },
    },
    User: {
      auditLogs: async (user: { id: string }) => {
        const result = await auditLogRepository.queryAuditLogs({
          actorId: user.id,
          limit: 50,
        });
        return result.data;
      },
    },
    AuditLog: {
      actor: async (auditLog: { userId: string }, _: any, context: any) => {
        return context.loaders.userLoader.load(auditLog.userId);
      },
    },
  },
});
