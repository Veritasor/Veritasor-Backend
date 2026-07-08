import { Router } from 'express';
import { createYoga, createSchema, type YogaServerInstance } from 'graphql-yoga';
import { GraphQLError, Kind, type DocumentNode } from 'graphql';
import { requireAuth } from '../middleware/requireAuth.js';
import { requirePermissions } from '../middleware/permissions.js';
import { IntegrationPermission } from '../types/permissions.js';
import * as auditLogRepository from '../repositories/auditLogRepository.js';
import * as businessRepository from '../repositories/business.js';
import * as userRepository from '../repositories/userRepository.js';
import { Counter } from 'prom-client';
import { metricsRegistry } from '../metrics.js';

const graphqlMutationRejections = new Counter({
  name: 'graphql_admin_mutation_rejections_total',
  help: 'Total number of mutations rejected on admin GraphQL endpoint',
  registers: [metricsRegistry],
});

const graphqlDepthLimitRejections = new Counter({
  name: 'graphql_admin_depth_limit_rejections_total',
  help: 'Total number of queries rejected due to depth limit on admin GraphQL endpoint',
  registers: [metricsRegistry],
});

const MAX_QUERY_DEPTH = 5;

const typeDefs = `
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
    users: [User!]!
    user(id: ID!): User
    auditLogs: [AuditLog!]!
    auditLog(id: ID!): AuditLog
    businesses: [Business!]!
    business(id: ID!): Business
  }
`;

const resolvers = {
  Query: {
    users: async () => {
      const users = await userRepository.getAllUsers();
      return users;
    },
    user: async (_: unknown, { id }: { id: string }) => {
      return userRepository.findUserById(id);
    },
    auditLogs: async () => {
      const result = await auditLogRepository.queryAuditLogs({ limit: 100 });
      return result.data;
    },
    auditLog: async (_: unknown, { id }: { id: string }) => {
      const logs = await auditLogRepository.getAllAuditLogs();
      return logs.find(l => l.id === id) || null;
    },
    businesses: async () => {
      return businessRepository.getAll();
    },
    business: async (_: unknown, { id }: { id: string }) => {
      return businessRepository.getById(id);
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
    actor: async (auditLog: { userId: string }) => {
      return userRepository.findUserById(auditLog.userId);
    },
  },
};

const schema = createSchema({ typeDefs, resolvers });

function getOperationDepth(document: DocumentNode): number {
  let maxDepth = 0;

  const walk = (selections: readonly any[], currentDepth: number) => {
    for (const selection of selections) {
      if (selection.kind === Kind.FIELD && selection.selectionSet) {
        walk(selection.selectionSet.selections, currentDepth + 1);
      }
    }
    if (currentDepth > maxDepth) {
      maxDepth = currentDepth;
    }
  };

  for (const definition of document.definitions) {
    if (definition.kind === Kind.OPERATION_DEFINITION && definition.operation === 'query') {
      walk(definition.selectionSet.selections, 1);
    }
  }

  return maxDepth;
}

export function createAdminGraphqlYoga(): YogaServerInstance<{}, {}> {
  return createYoga({
    schema,
    maskedErrors: true,
    plugins: [
      {
        onValidate({ params, setResult }: { params: { documentAST: DocumentNode; rules: readonly any[]; schema: any; typeInfo: any; options: any }; setResult: (errors: readonly GraphQLError[]) => void }) {
          const { documentAST } = params;

          for (const def of documentAST.definitions) {
            if (def.kind === Kind.OPERATION_DEFINITION) {
              if (def.operation === 'mutation') {
                graphqlMutationRejections.inc();
                setResult([new GraphQLError('Mutations are not allowed on this endpoint')]);
                return;
              }

              if (def.operation === 'query') {
                const depth = getOperationDepth(documentAST);
                if (depth > MAX_QUERY_DEPTH) {
                  graphqlDepthLimitRejections.inc();
                  setResult([
                    new GraphQLError(
                      `Query depth exceeds maximum allowed depth of ${MAX_QUERY_DEPTH}`,
                    ),
                  ]);
                  return;
                }
              }
            }
          }
        },
      },
    ],
  });
}

const adminGraphqlRouter = Router();

adminGraphqlRouter.use(requireAuth);
adminGraphqlRouter.use(
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
);

adminGraphqlRouter.use(createAdminGraphqlYoga());

export default adminGraphqlRouter;
