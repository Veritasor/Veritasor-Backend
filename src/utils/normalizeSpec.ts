/**
 * Deterministic normalizer for OpenAPI specification objects.
 *
 * Produces a stable, sorted representation of an OpenAPI spec so that
 * snapshot comparisons are immune to insertion-order variance and
 * non-semantic differences such as property reordering.
 *
 * Usage:
 *   import { normalizeSpec } from './normalizeSpec.js';
 *   const normalized = normalizeSpec(spec);
 *   const json = JSON.stringify(normalized, null, 2);
 *
 * @module src/utils/normalizeSpec
 */

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Recursively sort all object keys in a value.  Arrays are preserved in order
 * unless a domain-specific sorter applies (see `normalizeSpec`).
 */
function deepSortKeys(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value !== 'object') return value;

  if (Array.isArray(value)) {
    return value.map(deepSortKeys);
  }

  const sorted: Record<string, unknown> = {};
  const keys = Object.keys(value as Record<string, unknown>).sort();
  for (const key of keys) {
    sorted[key] = deepSortKeys((value as Record<string, unknown>)[key]);
  }
  return sorted;
}

/**
 * Sort an array of objects by a string property.
 */
function sortByProp<T extends Record<string, unknown>>(
  arr: T[],
  prop: string,
): T[] {
  return [...arr].sort((a, b) =>
    String(a[prop] ?? '').localeCompare(String(b[prop] ?? '')),
  );
}

/**
 * Sort response status code keys numerically (e.g. "200", "400", "401", "429").
 */
function sortResponseKeys(
  responses: Record<string, unknown>,
): Record<string, unknown> {
  const sorted: Record<string, unknown> = {};
  const keys = Object.keys(responses).sort((a, b) => {
    const numA = parseInt(a, 10);
    const numB = parseInt(b, 10);
    if (!isNaN(numA) && !isNaN(numB)) return numA - numB;
    return a.localeCompare(b);
  });
  for (const key of keys) {
    sorted[key] = responses[key];
  }
  return sorted;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Normalize an OpenAPI specification object for deterministic serialization.
 *
 * Applies the following transformations:
 * 1. All object keys are sorted alphabetically (recursive).
 * 2. `paths` keys are sorted alphabetically.
 * 3. `tags` array is sorted by `name`.
 * 4. `parameters` arrays within operations are sorted by `name`.
 * 5. `required` arrays within schemas are sorted alphabetically.
 * 6. Response status code keys within operations are sorted numerically.
 *
 * The function accepts `unknown` and returns `unknown` so it can be used
 * with any spec-like object without requiring strict type imports.
 *
 * @param spec  - An OpenAPI specification object (or any JSON-compatible value)
 * @returns     A deeply-sorted, normalized copy of the input
 */
export function normalizeSpec(spec: unknown): unknown {
  if (spec === null || spec === undefined || typeof spec !== 'object') {
    return spec;
  }

  const raw = spec as Record<string, unknown>;

  // 1. Sort tags by name
  if (Array.isArray(raw.tags)) {
    raw.tags = sortByProp(raw.tags as Record<string, unknown>[], 'name');
  }

  // 2. Sort paths keys and normalize each operation
  if (raw.paths && typeof raw.paths === 'object') {
    const pathsObj = raw.paths as Record<string, Record<string, unknown>>;
    const sortedPaths: Record<string, unknown> = {};
    const pathKeys = Object.keys(pathsObj).sort();

    for (const pathKey of pathKeys) {
      const pathItem = pathsObj[pathKey];
      const normalizedPathItem: Record<string, unknown> = {};
      const methods = Object.keys(pathItem).sort();

      for (const method of methods) {
        const operation = pathItem[method] as Record<string, unknown> | undefined;
        if (operation && typeof operation === 'object') {
          normalizedPathItem[method] = normalizeOperation(operation);
        } else {
          normalizedPathItem[method] = operation;
        }
      }

      sortedPaths[pathKey] = normalizedPathItem;
    }

    raw.paths = sortedPaths;
  }

  // 3. Sort component schema keys
  if (
    raw.components &&
    typeof raw.components === 'object' &&
    (raw.components as Record<string, unknown>).schemas &&
    typeof (raw.components as Record<string, unknown>).schemas === 'object'
  ) {
    const schemas = (raw.components as Record<string, unknown>).schemas as Record<string, unknown>;
    const sortedSchemas: Record<string, unknown> = {};
    for (const key of Object.keys(schemas).sort()) {
      sortedSchemas[key] = normalizeSchema(schemas[key] as Record<string, unknown>);
    }
    (raw.components as Record<string, unknown>).schemas = sortedSchemas;
  }

  // 4. Deep-sort everything
  return deepSortKeys(raw);
}

/**
 * Normalize an individual OpenAPI operation object.
 */
function normalizeOperation(op: Record<string, unknown>): Record<string, unknown> {
  const result = { ...op };

  // Sort parameters by name
  if (Array.isArray(result.parameters)) {
    result.parameters = sortByProp(
      result.parameters as Record<string, unknown>[],
      'name',
    );
  }

  // Sort response status keys numerically
  if (result.responses && typeof result.responses === 'object') {
    result.responses = sortResponseKeys(result.responses as Record<string, unknown>);
  }

  // Sort requestBody schema required arrays
  if (result.requestBody && typeof result.requestBody === 'object') {
    const rb = result.requestBody as Record<string, unknown>;
    if (rb.content && typeof rb.content === 'object') {
      const content = rb.content as Record<string, Record<string, unknown>>;
      for (const mediaType of Object.keys(content)) {
        const mediaObj = content[mediaType];
        if (mediaObj?.schema && typeof mediaObj.schema === 'object') {
          content[mediaType] = {
            ...mediaObj,
            schema: normalizeSchema(mediaObj.schema as Record<string, unknown>),
          };
        }
      }
    }
  }

  // Sort response body schemas
  if (result.responses && typeof result.responses === 'object') {
    const responses = result.responses as Record<string, Record<string, unknown>>;
    for (const code of Object.keys(responses)) {
      const resp = responses[code];
      if (resp?.content && typeof resp.content === 'object') {
        const content = resp.content as Record<string, Record<string, unknown>>;
        for (const mediaType of Object.keys(content)) {
          const mediaObj = content[mediaType];
          if (mediaObj?.schema && typeof mediaObj.schema === 'object') {
            content[mediaType] = {
              ...mediaObj,
              schema: normalizeSchema(mediaObj.schema as Record<string, unknown>),
            };
          }
        }
      }
    }
  }

  return result;
}

/**
 * Normalize an OpenAPI schema object — sort `required` arrays and
 * recurse into nested `properties`, `items`, and `oneOf`.
 */
function normalizeSchema(schema: Record<string, unknown>): Record<string, unknown> {
  const result = { ...schema };

  // Sort required array alphabetically
  if (Array.isArray(result.required)) {
    result.required = [...(result.required as string[])].sort();
  }

  // Recurse into properties
  if (result.properties && typeof result.properties === 'object') {
    const props = result.properties as Record<string, unknown>;
    const sortedProps: Record<string, unknown> = {};
    for (const key of Object.keys(props).sort()) {
      const val = props[key];
      if (val && typeof val === 'object' && !Array.isArray(val)) {
        sortedProps[key] = normalizeSchema(val as Record<string, unknown>);
      } else {
        sortedProps[key] = val;
      }
    }
    result.properties = sortedProps;
  }

  // Recurse into items
  if (result.items && typeof result.items === 'object' && !Array.isArray(result.items)) {
    result.items = normalizeSchema(result.items as Record<string, unknown>);
  }

  // Recurse into oneOf
  if (Array.isArray(result.oneOf)) {
    result.oneOf = (result.oneOf as Record<string, unknown>[]).map(normalizeSchema);
  }

  // Recurse into additionalProperties if it's a schema object
  if (
    result.additionalProperties &&
    typeof result.additionalProperties === 'object' &&
    !Array.isArray(result.additionalProperties)
  ) {
    result.additionalProperties = normalizeSchema(
      result.additionalProperties as Record<string, unknown>,
    );
  }

  return result;
}
