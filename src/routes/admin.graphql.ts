import { Router } from 'express';
import { createYoga, type YogaServerInstance } from 'graphql-yoga';
import { GraphQLError, Kind, type DocumentNode, type FieldNode, type ValidationContext, type ASTVisitor } from 'graphql';
import { usePersistedOperations } from '@graphql-yoga/plugin-persisted-operations';
import DataLoader from 'dataloader';
import { requireAuth } from '../middleware/requireAuth.js';
import { requirePermissions } from '../middleware/permissions.js';
import { IntegrationPermission } from '../types/permissions.js';
import * as businessRepository from '../repositories/business.js';
import * as userRepository from '../repositories/userRepository.js';
import * as attestationRepository from '../repositories/attestationRepository.js';
import { gatewaySchema } from '../graphql/gateway.js';
import { getPersistedQueryStore } from '../graphql/persistedQueries.js';
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

export const graphqlPersistedQueryRejections = new Counter({
  name: 'graphql_admin_persisted_query_rejections_total',
  help: 'Total number of non-persisted queries rejected on admin GraphQL endpoint',
  registers: [metricsRegistry],
});

const MAX_QUERY_DEPTH = 5;

export function createDataLoaders() {
  return {
    userLoader: new DataLoader(async (ids: readonly string[]) => {
      return userRepository.findUsersByIds(ids as string[]);
    }),
    businessLoader: new DataLoader(async (ids: readonly string[]) => {
      return businessRepository.getByIds(ids as string[]);
    }),
    attestationsByBusinessLoader: new DataLoader(async (businessIds: readonly string[]) => {
      return attestationRepository.listByBusinessIds(businessIds as string[]);
    }),
  };
}

function extractPersistedKey(params: any): string | undefined {
  if (!params) return undefined;
  if (params.extensions?.persistedQuery?.sha256Hash) {
    return params.extensions.persistedQuery.sha256Hash;
  }
  if (typeof params.extensions?.persistedQuery === 'string') {
    return params.extensions.persistedQuery;
  }
  return params.documentId || params.queryId;
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
    schema: gatewaySchema,
    maskedErrors: true,
    parserAndValidationCache: { validationCache: false },
    context: () => ({
      loaders: createDataLoaders(),
    }),
    plugins: [
      {
        onParams({ params, setResult }) {
          if (!config.graphql.allowArbitraryOperations) {
            const store = getPersistedQueryStore();
            const key = extractPersistedKey(params);
            if (!key && params.query) {
              graphqlPersistedQueryRejections.inc();
              setResult({
                errors: [
                  new GraphQLError('Persisted queries only allowed', {
                    extensions: { code: 'PERSISTED_QUERY_ONLY' },
                  }),
                ],
              });
            } else if (key && !store.has(key)) {
              graphqlPersistedQueryRejections.inc();
              setResult({
                errors: [
                  new GraphQLError('Persisted query not found', {
                    extensions: { code: 'PERSISTED_QUERY_NOT_FOUND' },
                  }),
                ],
              });
            }
          }
        },
        async onResponse({ response, setResponse }) {
          if (!config.graphql.allowArbitraryOperations && response.status === 200) {
            const clone = response.clone();
            try {
              const body = await clone.json();
              if (body?.errors && body.errors.length > 0) {
                setResponse(
                  new Response(JSON.stringify(body), {
                    status: 400,
                    headers: response.headers,
                  })
                );
              }
            } catch (e) {
              // Ignore non-json responses
            }
          }
        },
      },
      usePersistedOperations({
        getPersistedOperation: (key: string) => {
          const store = getPersistedQueryStore();
          return store.get(key);
        },
        allowArbitraryOperations: (_request) => {
          return config.graphql.allowArbitraryOperations;
        },
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
