import { Router } from 'express';
import { createYoga, createSchema, type YogaServerInstance } from 'graphql-yoga';
import { GraphQLError, Kind, type DocumentNode, type FieldNode, type ValidationContext, type ASTVisitor } from 'graphql';
import { requireAuth } from '../middleware/requireAuth.js';
import { requirePermissions } from '../middleware/permissions.js';
import { IntegrationPermission } from '../types/permissions.js';
import * as businessRepository from '../repositories/business.js';
import * as userRepository from '../repositories/userRepository.js';
import { Counter } from 'prom-client';
import { metricsRegistry } from '../metrics.js';
import { config } from '../config/index.js';

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

const graphqlIntrospectionRejections = new Counter({
  name: 'graphql_admin_introspection_rejections_total',
  help: 'Total number of introspection queries rejected on admin GraphQL endpoint',
  registers: [metricsRegistry],
});

const MAX_QUERY_DEPTH = 5;



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

const INTROSPECTION_FIELD_NAMES = new Set(['__schema', '__type']);

function containsIntrospectionField(
  selections: readonly any[],
  fragmentMap: Map<string, any>,
): boolean {
  for (const selection of selections) {
    if (selection.kind === Kind.FIELD) {
      if (INTROSPECTION_FIELD_NAMES.has((selection as FieldNode).name.value)) {
        return true;
      }
      if (selection.selectionSet?.selections) {
        if (containsIntrospectionField(selection.selectionSet.selections, fragmentMap)) {
          return true;
        }
      }
    } else if (selection.kind === Kind.INLINE_FRAGMENT && selection.selectionSet?.selections) {
      if (containsIntrospectionField(selection.selectionSet.selections, fragmentMap)) {
        return true;
      }
    } else if (selection.kind === Kind.FRAGMENT_SPREAD) {
      const fragment = fragmentMap.get(selection.name.value);
      if (fragment?.selectionSet?.selections) {
        if (containsIntrospectionField(fragment.selectionSet.selections, fragmentMap)) {
          return true;
        }
      }
    }
  }
  return false;
}

function isIntrospectionQuery(document: DocumentNode): boolean {
  const fragmentMap = new Map<string, any>();
  for (const def of document.definitions) {
    if (def.kind === Kind.FRAGMENT_DEFINITION) {
      fragmentMap.set(def.name.value, def);
    }
  }
  for (const def of document.definitions) {
    if (def.kind === Kind.OPERATION_DEFINITION) {
      if (containsIntrospectionField(def.selectionSet.selections, fragmentMap)) {
        return true;
      }
    }
  }
  return false;
}

function introspectionGateRule(context: ValidationContext): ASTVisitor {
  return {
    Document(node) {
      if (!config.graphql.enableIntrospection && isIntrospectionQuery(node)) {
        graphqlIntrospectionRejections.inc();
        context.reportError(
          new GraphQLError('Introspection is not allowed on this endpoint'),
        );
      }
    },
  };
}

export function createAdminGraphqlYoga(): YogaServerInstance<{}, {}> {
  return createYoga({
    schema,
    maskedErrors: true,
    parserAndValidationCache: { validationCache: false },
    plugins: [
      usePersistedOperations({
        getPersistedOperation: async (key: string) => {
          const store = await getPersistedQueryStore();
          return store.get(key);
        },
        allowArbitraryOperations: false,
      }),
      {
        onValidate({ addValidationRule }: { addValidationRule: (rule: any) => void }) {
          addValidationRule(introspectionGateRule);
        },
      },
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
          const key = `graphql-budget:{${userId}}`;
          
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
              errors: [new GraphQLError(`Query cost of ${cost} exceeds remaining budget of ${remaining}.`)]
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
