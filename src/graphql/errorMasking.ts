import { GraphQLError } from 'graphql';
import { isAppError, AppError } from '../types/errors.js';
import { logger } from '../utils/logger.js'; // Assuming a logger exists, need to find it

export function maskGraphQLError(error: unknown, message: string): GraphQLError {
  // 1. Log the full error for server-side debugging
  logger.error('GraphQL Error:', error);

  // 2. Determine the VRT code
  let vrtCode = 'VRT-9999'; // Default to generic internal error
  let statusCode = 500;

  if (isAppError(error)) {
    vrtCode = error.code; // Assuming AppError has a 'code' field for VRT code
    statusCode = error.statusCode;
  } else if (error instanceof GraphQLError) {
      // Handle specific GraphQL errors (e.g., validation, persisted query)
      if (error.extensions?.code === 'PERSISTED_QUERY_NOT_FOUND') {
          vrtCode = 'VRT-0004';
          statusCode = 404;
      }
      // ... handle other GraphQL errors
  }

  // 3. Return a masked error
  return new GraphQLError(message, {
    extensions: {
      code: vrtCode,
      http: { status: statusCode },
    },
  });
}
