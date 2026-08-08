import { GraphQLError } from 'graphql';
import { maskGraphQLError } from '../../../src/graphql/errorMasking.js';
import { AppError } from '../../../src/types/errors.js';

describe('maskGraphQLError', () => {
  it('should mask AppError and return VRT code', () => {
    const appError = new AppError('Internal DB error', 500, 'VRT-0007');
    const masked = maskGraphQLError(appError, 'Internal Server Error');
    expect(masked.extensions?.code).toBe('VRT-0007');
    expect(masked.message).toBe('Internal Server Error');
  });

  it('should mask Persisted Query error', () => {
    const gqlError = new GraphQLError('Query not found', {
      extensions: { code: 'PERSISTED_QUERY_NOT_FOUND' },
    });
    const masked = maskGraphQLError(gqlError, 'Query not found');
    expect(masked.extensions?.code).toBe('VRT-0004');
  });

  it('should mask unknown error to VRT-9999', () => {
    const error = new Error('Random system crash');
    const masked = maskGraphQLError(error, 'Internal Server Error');
    expect(masked.extensions?.code).toBe('VRT-9999');
  });
});
