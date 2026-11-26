/**
 * Unit tests for OpenAPI spec normalization.
 *
 * Tests verify that `normalizeSpec` produces deterministic, idempotent output
 * regardless of input ordering, and handles edge cases correctly.
 *
 * @module tests/unit/utils/normalizeSpec
 */

import { describe, it, expect } from 'vitest';
import { normalizeSpec } from '../../../src/utils/normalizeSpec.js';

// ─── Helper: verify object keys are sorted ─────────────────────────────────────

function isObjectKeysSorted(obj: Record<string, unknown>): boolean {
  const keys = Object.keys(obj);
  return JSON.stringify(keys) === JSON.stringify([...keys].sort());
}

// ─── Idempotency tests ─────────────────────────────────────────────────────────

describe('normalizeSpec — idempotency', () => {
  it('normalizing twice produces identical output', () => {
    const spec = {
      openapi: '3.1.0',
      info: { title: 'Test API', version: '1.0.0' },
      paths: {
        '/api/users': {
          get: {
            summary: 'Get users',
            responses: { '200': { description: 'OK' } },
          },
        },
      },
    };

    const first = normalizeSpec(spec);
    const second = normalizeSpec(first);

    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });

  it('normalizing three times is still idempotent', () => {
    const spec = {
      openapi: '3.1.0',
      tags: [{ name: 'auth' }, { name: 'users' }],
      paths: {
        '/api/auth/login': {
          post: {
            tags: ['auth'],
            responses: { '200': { description: 'OK' }, '401': { description: 'Unauthorized' } },
          },
        },
      },
    };

    const first = normalizeSpec(spec);
    const second = normalizeSpec(first);
    const third = normalizeSpec(second);

    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    expect(JSON.stringify(second)).toBe(JSON.stringify(third));
  });

  it('already-normalized input is unchanged', () => {
    const spec = {
      info: { title: 'Test' },
      paths: {},
    };

    const first = normalizeSpec(spec);
    const second = normalizeSpec(first);

    expect(first).toEqual(second);
  });
});

// ─── Key ordering tests ────────────────────────────────────────────────────────

describe('normalizeSpec — key ordering', () => {
  it('sorts top-level object keys alphabetically', () => {
    const spec = {
      zebra: 1,
      apple: 2,
      middle: 3,
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const keys = Object.keys(normalized);

    expect(keys).toEqual(['apple', 'middle', 'zebra']);
  });

  it('sorts nested object keys alphabetically', () => {
    const spec = {
      info: {
        version: '1.0.0',
        title: 'Test API',
        description: 'A test',
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const info = normalized.info as Record<string, unknown>;
    const keys = Object.keys(info);

    expect(keys).toEqual(['description', 'title', 'version']);
  });

  it('sorts keys at all nesting levels', () => {
    const spec = {
      level1: {
        z: 1,
        a: {
          nestedZ: 2,
          nestedA: 3,
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const level1 = normalized.level1 as Record<string, unknown>;
    const nested = level1.a as Record<string, unknown>;

    expect(Object.keys(level1)).toEqual(['a', 'z']);
    expect(Object.keys(nested)).toEqual(['nestedA', 'nestedZ']);
  });

  it('sorts paths keys alphabetically', () => {
    const spec = {
      paths: {
        '/api/zebra': {},
        '/api/apple': {},
        '/api/middle': {},
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const paths = normalized.paths as Record<string, unknown>;
    const keys = Object.keys(paths);

    expect(keys).toEqual(['/api/apple', '/api/middle', '/api/zebra']);
  });

  it('sorts method keys within path items alphabetically', () => {
    const spec = {
      paths: {
        '/api/test': {
          post: {},
          get: {},
          delete: {},
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const paths = normalized.paths as Record<string, unknown>;
    const testPath = paths['/api/test'] as Record<string, unknown>;
    const keys = Object.keys(testPath);

    expect(keys).toEqual(['delete', 'get', 'post']);
  });
});

// ─── Array sorting tests ───────────────────────────────────────────────────────

describe('normalizeSpec — array sorting', () => {
  it('sorts tags array by name property', () => {
    const spec = {
      tags: [
        { name: 'zebra', description: 'Z' },
        { name: 'apple', description: 'A' },
        { name: 'middle', description: 'M' },
      ],
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const tags = normalized.tags as { name: string }[];
    const names = tags.map((t) => t.name);

    expect(names).toEqual(['apple', 'middle', 'zebra']);
  });

  it('sorts parameters array by name property', () => {
    const spec = {
      paths: {
        '/api/test': {
          get: {
            parameters: [
              { name: 'zebra', in: 'query' },
              { name: 'apple', in: 'query' },
              { name: 'middle', in: 'query' },
            ],
          },
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const paths = normalized.paths as Record<string, unknown>;
    const getOp = (paths['/api/test'] as Record<string, unknown>).get as Record<string, unknown>;
    const params = getOp.parameters as { name: string }[];
    const names = params.map((p) => p.name);

    expect(names).toEqual(['apple', 'middle', 'zebra']);
  });

  it('sorts required arrays alphabetically', () => {
    const spec = {
      components: {
        schemas: {
          User: {
            required: ['zebra', 'apple', 'middle'],
          },
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const schemas = (normalized.components as Record<string, unknown>).schemas as Record<string, unknown>;
    const user = schemas.User as Record<string, unknown>;
    const required = user.required as string[];

    expect(required).toEqual(['apple', 'middle', 'zebra']);
  });

  it('sorts response status codes numerically', () => {
    const spec = {
      paths: {
        '/api/test': {
          get: {
            responses: {
              '401': { description: 'Unauthorized' },
              '200': { description: 'OK' },
              '429': { description: 'Too Many Requests' },
              '500': { description: 'Server Error' },
            },
          },
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const paths = normalized.paths as Record<string, unknown>;
    const getOp = (paths['/api/test'] as Record<string, unknown>).get as Record<string, unknown>;
    const responses = getOp.responses as Record<string, unknown>;
    const codes = Object.keys(responses);

    expect(codes).toEqual(['200', '401', '429', '500']);
  });

  it('handles mixed numeric and string response codes', () => {
    const spec = {
      paths: {
        '/api/test': {
          get: {
            responses: {
              default: { description: 'Default' },
              '200': { description: 'OK' },
              '404': { description: 'Not Found' },
            },
          },
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const paths = normalized.paths as Record<string, unknown>;
    const getOp = (paths['/api/test'] as Record<string, unknown>).get as Record<string, unknown>;
    const responses = getOp.responses as Record<string, unknown>;
    const codes = Object.keys(responses);

    // Numeric codes sorted first, then alphabetical for non-numeric
    expect(codes).toEqual(['200', '404', 'default']);
  });

  it('preserves array order when no domain-specific sorting applies', () => {
    const spec = {
      values: [3, 1, 2],
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const values = normalized.values as number[];

    expect(values).toEqual([3, 1, 2]); // Not sorted - arrays are preserved
  });
});

// ─── Schema normalization tests ───────────────────────────────────────────────

describe('normalizeSpec — schema normalization', () => {
  it('sorts schema properties keys alphabetically', () => {
    const spec = {
      components: {
        schemas: {
          User: {
            properties: {
              zebra: { type: 'string' },
              apple: { type: 'string' },
              middle: { type: 'string' },
            },
          },
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const schemas = (normalized.components as Record<string, unknown>).schemas as Record<string, unknown>;
    const user = schemas.User as Record<string, unknown>;
    const props = user.properties as Record<string, unknown>;
    const keys = Object.keys(props);

    expect(keys).toEqual(['apple', 'middle', 'zebra']);
  });

  it('recursively normalizes nested schema properties', () => {
    const spec = {
      components: {
        schemas: {
          User: {
            properties: {
              address: {
                properties: {
                  zebra: { type: 'string' },
                  apple: { type: 'string' },
                },
              },
            },
          },
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const schemas = (normalized.components as Record<string, unknown>).schemas as Record<string, unknown>;
    const user = schemas.User as Record<string, unknown>;
    const props = user.properties as Record<string, unknown>;
    const address = props.address as Record<string, unknown>;
    const addressProps = address.properties as Record<string, unknown>;
    const keys = Object.keys(addressProps);

    expect(keys).toEqual(['apple', 'zebra']);
  });

  it('normalizes items schema in array types', () => {
    const spec = {
      components: {
        schemas: {
          ItemArray: {
            items: {
              properties: {
                zebra: { type: 'string' },
                apple: { type: 'string' },
              },
            },
          },
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const schemas = (normalized.components as Record<string, unknown>).schemas as Record<string, unknown>;
    const itemArray = schemas.ItemArray as Record<string, unknown>;
    const items = itemArray.items as Record<string, unknown>;
    const props = items.properties as Record<string, unknown>;
    const keys = Object.keys(props);

    expect(keys).toEqual(['apple', 'zebra']);
  });

  it('normalizes oneOf array schemas', () => {
    const spec = {
      components: {
        schemas: {
          Union: {
            oneOf: [
              { properties: { zebra: { type: 'string' } } },
              { properties: { apple: { type: 'string' } } },
            ],
          },
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const schemas = (normalized.components as Record<string, unknown>).schemas as Record<string, unknown>;
    const union = schemas.Union as Record<string, unknown>;
    const oneOf = union.oneOf as Record<string, unknown>[];

    // oneOf items should be normalized individually
    expect(oneOf).toHaveLength(2);
    expect(isObjectKeysSorted(oneOf[0] as Record<string, unknown>)).toBe(true);
    expect(isObjectKeysSorted(oneOf[1] as Record<string, unknown>)).toBe(true);
  });

  it('normalizes additionalProperties when it is a schema object', () => {
    const spec = {
      components: {
        schemas: {
          Dynamic: {
            additionalProperties: {
              properties: {
                zebra: { type: 'string' },
                apple: { type: 'string' },
              },
            },
          },
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const schemas = (normalized.components as Record<string, unknown>).schemas as Record<string, unknown>;
    const dynamic = schemas.Dynamic as Record<string, unknown>;
    const additionalProps = dynamic.additionalProperties as Record<string, unknown>;
    const props = additionalProps.properties as Record<string, unknown>;
    const keys = Object.keys(props);

    expect(keys).toEqual(['apple', 'zebra']);
  });

  it('normalizes requestBody content schemas', () => {
    const spec = {
      paths: {
        '/api/test': {
          post: {
            requestBody: {
              content: {
                'application/json': {
                  schema: {
                    required: ['zebra', 'apple'],
                    properties: {
                      zebra: { type: 'string' },
                      apple: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const paths = normalized.paths as Record<string, unknown>;
    const postOp = (paths['/api/test'] as Record<string, unknown>).post as Record<string, unknown>;
    const requestBody = postOp.requestBody as Record<string, unknown>;
    const content = requestBody.content as Record<string, unknown>;
    const jsonSchema = (content['application/json'] as Record<string, unknown>).schema as Record<string, unknown>;

    expect(jsonSchema.required).toEqual(['apple', 'zebra']);
    expect(Object.keys(jsonSchema.properties as Record<string, unknown>)).toEqual(['apple', 'zebra']);
  });

  it('normalizes response content schemas', () => {
    const spec = {
      paths: {
        '/api/test': {
          get: {
            responses: {
              '200': {
                content: {
                  'application/json': {
                    schema: {
                      required: ['zebra', 'apple'],
                      properties: {
                        zebra: { type: 'string' },
                        apple: { type: 'string' },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const paths = normalized.paths as Record<string, unknown>;
    const getOp = (paths['/api/test'] as Record<string, unknown>).get as Record<string, unknown>;
    const responses = getOp.responses as Record<string, unknown>;
    const response200 = responses['200'] as Record<string, unknown>;
    const content = response200.content as Record<string, unknown>;
    const jsonSchema = (content['application/json'] as Record<string, unknown>).schema as Record<string, unknown>;

    expect(jsonSchema.required).toEqual(['apple', 'zebra']);
    expect(Object.keys(jsonSchema.properties as Record<string, unknown>)).toEqual(['apple', 'zebra']);
  });
});

// ─── Edge case tests ───────────────────────────────────────────────────────────

describe('normalizeSpec — edge cases', () => {
  it('handles null input', () => {
    const result = normalizeSpec(null);
    expect(result).toBe(null);
  });

  it('handles undefined input', () => {
    const result = normalizeSpec(undefined);
    expect(result).toBe(undefined);
  });

  it('handles primitive values', () => {
    expect(normalizeSpec(42)).toBe(42);
    expect(normalizeSpec('string')).toBe('string');
    expect(normalizeSpec(true)).toBe(true);
    expect(normalizeSpec(false)).toBe(false);
  });

  it('handles empty object', () => {
    const result = normalizeSpec({});
    expect(result).toEqual({});
  });

  it('handles empty array', () => {
    const result = normalizeSpec([]);
    expect(result).toEqual([]);
  });

  it('handles empty paths object', () => {
    const spec = {
      paths: {},
    };

    const result = normalizeSpec(spec) as Record<string, unknown>;
    expect(result.paths).toEqual({});
  });

  it('handles empty tags array', () => {
    const spec = {
      tags: [],
    };

    const result = normalizeSpec(spec) as Record<string, unknown>;
    expect(result.tags).toEqual([]);
  });

  it('handles missing optional fields', () => {
    const spec = {
      openapi: '3.1.0',
    };

    const result = normalizeSpec(spec);
    expect(result).toBeDefined();
  });

  it('handles $ref-only schemas without crashing', () => {
    const spec = {
      components: {
        schemas: {
          RefOnly: {
            $ref: '#/components/schemas/Other',
          },
        },
      },
    };

    const result = normalizeSpec(spec);
    expect(result).toBeDefined();
  });

  it('handles schemas with only $ref and no properties', () => {
    const spec = {
      components: {
        schemas: {
          User: {
            $ref: '#/components/schemas/BaseUser',
          },
          BaseUser: {
            type: 'object',
          },
        },
      },
    };

    const result = normalizeSpec(spec);
    expect(result).toBeDefined();
  });

  it('handles nested null values', () => {
    const spec = {
      info: {
        title: 'Test',
        description: null,
      },
    };

    const result = normalizeSpec(spec) as Record<string, unknown>;
    const info = result.info as Record<string, unknown>;
    expect(info.description).toBe(null);
  });

  it('handles arrays containing null', () => {
    const spec = {
      values: [1, null, 3],
    };

    const result = normalizeSpec(spec) as Record<string, unknown>;
    const values = result.values as unknown[];
    expect(values).toEqual([1, null, 3]);
  });

  it('handles objects with null values', () => {
    const spec = {
      field: null,
      other: 'value',
    };

    const result = normalizeSpec(spec) as Record<string, unknown>;
    expect(result.field).toBe(null);
    expect(result.other).toBe('value');
  });

  it('handles deeply nested structures', () => {
    const spec = {
      level1: {
        level2: {
          level3: {
            level4: {
              zebra: 1,
              apple: 2,
            },
          },
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const level4 = (normalized.level1 as Record<string, unknown>).level2 as Record<string, unknown>;
    const level3 = level4.level3 as Record<string, unknown>;
    const level4Obj = level3.level4 as Record<string, unknown>;
    const keys = Object.keys(level4Obj);

    expect(keys).toEqual(['apple', 'zebra']);
  });

  it('handles arrays of objects (no sorting applied)', () => {
    const spec = {
      items: [
        { id: 3, name: 'c' },
        { id: 1, name: 'a' },
        { id: 2, name: 'b' },
      ],
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const items = normalized.items as Record<string, unknown>[];

    // Array order should be preserved, but object keys within each item should be sorted
    expect(items).toHaveLength(3);
    expect(items[0]).toEqual({ id: 3, name: 'c' });
    expect(items[1]).toEqual({ id: 1, name: 'a' });
    expect(items[2]).toEqual({ id: 2, name: 'b' });
  });

  it('handles missing components section', () => {
    const spec = {
      openapi: '3.1.0',
      info: { title: 'Test' },
      paths: {},
    };

    const result = normalizeSpec(spec);
    expect(result).toBeDefined();
  });

  it('handles missing schemas in components', () => {
    const spec = {
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer' },
        },
      },
    };

    const result = normalizeSpec(spec);
    expect(result).toBeDefined();
  });

  it('handles operation without parameters', () => {
    const spec = {
      paths: {
        '/api/test': {
          get: {
            summary: 'Test',
            responses: { '200': { description: 'OK' } },
          },
        },
      },
    };

    const result = normalizeSpec(spec);
    expect(result).toBeDefined();
  });

  it('handles operation without responses', () => {
    const spec = {
      paths: {
        '/api/test': {
          get: {
            summary: 'Test',
          },
        },
      },
    };

    const result = normalizeSpec(spec);
    expect(result).toBeDefined();
  });

  it('handles non-object additionalProperties (boolean)', () => {
    const spec = {
      components: {
        schemas: {
          Dynamic: {
            additionalProperties: true,
          },
        },
      },
    };

    const result = normalizeSpec(spec) as Record<string, unknown>;
    const schemas = (result.components as Record<string, unknown>).schemas as Record<string, unknown>;
    const dynamic = schemas.Dynamic as Record<string, unknown>;
    expect(dynamic.additionalProperties).toBe(true);
  });

  it('handles non-object items (primitive)', () => {
    const spec = {
      components: {
        schemas: {
          StringArray: {
            items: { type: 'string' },
          },
        },
      },
    };

    const result = normalizeSpec(spec);
    expect(result).toBeDefined();
  });
});

// ─── Determinism tests ─────────────────────────────────────────────────────────

describe('normalizeSpec — determinism', () => {
  it('produces identical output for same input with different key order', () => {
    const spec1 = {
      zebra: 1,
      apple: 2,
      middle: 3,
    };

    const spec2 = {
      apple: 2,
      middle: 3,
      zebra: 1,
    };

    const normalized1 = normalizeSpec(spec1);
    const normalized2 = normalizeSpec(spec2);

    expect(JSON.stringify(normalized1)).toBe(JSON.stringify(normalized2));
  });

  it('produces identical JSON string across multiple calls', () => {
    const spec = {
      openapi: '3.1.0',
      info: { title: 'Test', version: '1.0.0' },
      paths: {
        '/api/users': {
          get: { responses: { '200': { description: 'OK' } } },
        },
      },
    };

    const json1 = JSON.stringify(normalizeSpec(spec), null, 2);
    const json2 = JSON.stringify(normalizeSpec(spec), null, 2);
    const json3 = JSON.stringify(normalizeSpec(spec), null, 2);

    expect(json1).toBe(json2);
    expect(json2).toBe(json3);
  });

  it('handles shuffled tags deterministically', () => {
    const spec1 = {
      tags: [{ name: 'auth' }, { name: 'users' }, { name: 'admin' }],
    };

    const spec2 = {
      tags: [{ name: 'admin' }, { name: 'auth' }, { name: 'users' }],
    };

    const normalized1 = normalizeSpec(spec1) as Record<string, unknown>;
    const normalized2 = normalizeSpec(spec2) as Record<string, unknown>;

    expect(JSON.stringify(normalized1)).toBe(JSON.stringify(normalized2));
  });

  it('handles shuffled paths deterministically', () => {
    const spec1 = {
      paths: {
        '/api/users': {},
        '/api/auth': {},
        '/api/admin': {},
      },
    };

    const spec2 = {
      paths: {
        '/api/admin': {},
        '/api/auth': {},
        '/api/users': {},
      },
    };

    const normalized1 = normalizeSpec(spec1) as Record<string, unknown>;
    const normalized2 = normalizeSpec(spec2) as Record<string, unknown>;

    expect(JSON.stringify(normalized1)).toBe(JSON.stringify(normalized2));
  });
});

// ─── Component schema key ordering ───────────────────────────────────────────────

describe('normalizeSpec — component schemas', () => {
  it('sorts component schema keys alphabetically', () => {
    const spec = {
      components: {
        schemas: {
          Zebra: { type: 'object' },
          Apple: { type: 'object' },
          Middle: { type: 'object' },
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const schemas = (normalized.components as Record<string, unknown>).schemas as Record<string, unknown>;
    const keys = Object.keys(schemas);

    expect(keys).toEqual(['Apple', 'Middle', 'Zebra']);
  });

  it('normalizes each schema in components', () => {
    const spec = {
      components: {
        schemas: {
          User: {
            required: ['email', 'password'],
            properties: {
              password: { type: 'string' },
              email: { type: 'string' },
            },
          },
        },
      },
    };

    const normalized = normalizeSpec(spec) as Record<string, unknown>;
    const schemas = (normalized.components as Record<string, unknown>).schemas as Record<string, unknown>;
    const user = schemas.User as Record<string, unknown>;

    expect(user.required).toEqual(['email', 'password']);
    expect(Object.keys(user.properties as Record<string, unknown>)).toEqual(['email', 'password']);
  });
});

// ─── Input mutation behavior ───────────────────────────────────────────────────

describe('normalizeSpec — input mutation behavior', () => {
  it('mutates the input object properties during processing', () => {
    const spec = {
      zebra: 1,
      apple: 2,
      paths: {
        '/api/zebra': {},
        '/api/apple': {},
      },
    };

    const originalPathKeys = Object.keys(spec.paths);

    normalizeSpec(spec);

    // The original paths object is mutated (sorted in place)
    expect(Object.keys(spec.paths)).not.toEqual(originalPathKeys);
    expect(Object.keys(spec.paths)).toEqual(['/api/apple', '/api/zebra']);
  });

  it('returns a new object reference, not the input', () => {
    const spec = { test: 1 };
    const normalized = normalizeSpec(spec);

    // The result is a new object reference (deepSortKeys creates a new object)
    expect(normalized).not.toBe(spec);
    // But the values are equal
    expect(normalized).toEqual(spec);
  });
});
