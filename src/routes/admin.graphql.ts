import { Router } from 'express';
import { createYoga, createSchema, type YogaServerInstance } from 'graphql-yoga';
import { GraphQLError, Kind, type DocumentNode, TypeInfo, visit, visitWithTypeInfo } from 'graphql';
import { requireAuth } from '../middleware/requireAuth.js';
import { requirePermissions } from '../middleware/permissions.js';
import { IntegrationPermission } from '../types/permissions.js';
import * as auditLogRepository from '../repositories/auditLogRepository.js';
import * as businessRepository from '../repositories/business.js';
import * as userRepository from '../repositories/userRepository.js';
import { Counter } from 'prom-client';
import { metricsRegistry } from '../metrics.js';
import { getRedisClient } from '../redis.js';

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

const graphqlCostExhaustionRejections = new Counter({
  name: 'graphql_admin_cost_exhaustion_rejections_total',
  help: 'Total number of queries rejected due to cost budget exhaustion on admin GraphQL endpoint',
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
    user: User
    attestations: [Attestation!]
  }

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
    auditLogs: async (user: { id: string }, _: any, context: any) => {
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
  Business: {
    user: async (business: { userId: string }, _: any, context: any) => {
      return context.loaders.userLoader.load(business.userId);
    },
    attestations: async (business: { id: string }, _: any, context: any) => {
      return context.loaders.attestationsByBusinessLoader.load(business.id);
    },
  },
};

export function createDataLoaders() {
  return {
    userLoader: new DataLoader(async (ids: readonly string[]) => {
      return userRepository.findUsersByIds(ids);
    }),
    businessLoader: new DataLoader(async (ids: readonly string[]) => {
      return businessRepository.getByIds(ids);
    }),
    attestationsByBusinessLoader: new DataLoader(async (businessIds: readonly string[]) => {
      return attestationRepository.listByBusinessIds(businessIds);
    }),
  };
}

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

function getOperationCost(document: DocumentNode): number {
  const typeInfo = new TypeInfo(schema);
  let cost = 0;
  visit(
    document,
    visitWithTypeInfo(typeInfo, {
      Field(node) {
        cost += 1;
        const type = typeInfo.getType();
        if (type && type.toString().startsWith('[')) {
          cost += 2; // lists cost more
        }
      },
    })
  );
  return cost;
}

class TokenBucketStore {
  async consume(key: string, tokensToConsume: number, maxTokens: number, refillRateMs: number): Promise<{ allowed: boolean; remaining: number }> {
    try {
      if (!process.env.REDIS_URL && !process.env.REDIS_CLUSTER_NODES) {
        return { allowed: true, remaining: maxTokens };
      }
      const client = getRedisClient();
      const now = Date.now();
      const result = await (client as any).eval(
        \`local key = KEYS[1]
         local tokensToConsume = tonumber(ARGV[1])
         local maxTokens = tonumber(ARGV[2])
         local refillRate = tonumber(ARGV[3])
         local now = tonumber(ARGV[4])
         
         local bucket = redis.call('HMGET', key, 'tokens', 'lastRefill')
         local tokens = tonumber(bucket[1])
         local lastRefill = tonumber(bucket[2])
         
         if not tokens then
           tokens = maxTokens
           lastRefill = now
         else
           local timePassed = math.max(0, now - lastRefill)
           local newTokens = math.floor(timePassed * refillRate)
           tokens = math.min(maxTokens, tokens + newTokens)
           if newTokens > 0 then
             lastRefill = lastRefill + (newTokens / refillRate)
           end
         end
         
         if tokens >= tokensToConsume then
           tokens = tokens - tokensToConsume
           redis.call('HMSET', key, 'tokens', tokens, 'lastRefill', lastRefill)
           local timeToMax = math.ceil((maxTokens - tokens) / refillRate)
           redis.call('PEXPIRE', key, timeToMax)
           return {1, tokens}
         else
           return {0, tokens}
         end\`,
        1,
        key,
        tokensToConsume,
        maxTokens,
        refillRateMs,
        now
      );
      return { allowed: result[0] === 1, remaining: result[1] };
    } catch (error) {
      return { allowed: true, remaining: maxTokens };
    }
  }
}

const tokenBucketStore = new TokenBucketStore();

export function createAdminGraphqlYoga(): YogaServerInstance<{}, {}> {
  return createYoga({
    schema,
    maskedErrors: true,
    context: (req) => ({
      ...req,
      loaders: createDataLoaders(),
    }),
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
                      \`Query depth exceeds maximum allowed depth of \${MAX_QUERY_DEPTH}\`,
                    ),
                  ]);
                  return;
                }
              }
            }
          }
        },
        async onExecute({ args, setResultAndStop }) {
          const { document, contextValue } = args;
          const cost = getOperationCost(document);
          const req = (contextValue as any).req;
          const res = (contextValue as any).res;
          const userId = req?.user?.userId || 'anonymous';
          const key = \`graphql-budget:{\${userId}}\`;
          
          const maxTokens = 1000;
          const refillRateMs = 1000 / 60000; // 1000 tokens per minute
          
          const { allowed, remaining } = await tokenBucketStore.consume(key, cost, maxTokens, refillRateMs);
          
          if (res && res.setHeader) {
            res.setHeader('X-GraphQL-Cost', cost.toString());
            res.setHeader('X-GraphQL-Budget-Remaining', remaining.toString());
          }
          
          if (!allowed) {
            graphqlCostExhaustionRejections.inc();
            setResultAndStop({
              errors: [new GraphQLError(\`Query cost of \${cost} exceeds remaining budget of \${remaining}.\`)]
            });
            return;
          }
        }
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
