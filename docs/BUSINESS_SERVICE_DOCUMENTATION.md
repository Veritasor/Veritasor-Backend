/**
 * Business Service - Input Normalization Documentation
 *
 * This document describes the business service input validation and normalization
 * system implemented as part of issue #119.
 *
 * @document Business Service Architecture
 */

# Business Service Input Normalization

## Overview

The business service implements comprehensive input validation and normalization using Zod schemas and custom normalization utilities. This ensures data quality, security, and consistency across the business domain.

---

## Architecture

The business service follows a layered approach to ensure all data is validated and cleaned before reaching the database:

```text
HTTP Request
    ↓
validateBody Middleware (Zod schema validation)
    ↓
Service Handler (Business Logic + Normalization)
    ↓
Repository (Database Operations)
    ↓
HTTP Response
```

---

## Components

### 1. Validation Schemas (`src/services/business/schemas.ts`)

Zod-based schemas validate the exact structure and content of incoming payloads before processing.

```typescript
// Create business input
const input = {
  name: "Acme Corporation",           // Required, 1-255 chars
  industry: "Technology",             // Optional, 0-100 chars
  description: "Our mission...",      // Optional, 0-2000 chars
  website: "https://acme.com"         // Optional, 0-2048 chars, valid URL
};

const validated = await parseCreateBusinessInput(input);
```

### 2. Normalization Functions (`src/services/business/normalize.ts`)

Dedicated utilities guarantee consistent data transformation formatting:

- `normalizeName()` - Trim and collapse whitespace
- `normalizeUrl()` - Add protocol, lowercase, remove trailing slashes
- `normalizeIndustry()` - Trim and normalize spaces
- `normalizeDescription()` - Normalize while preserving newlines
- `formatForStorage()` - Complete formatting for database

### 3. Service Handlers

**Create Business** (`src/services/business/create.ts`):
- Validates authenticated user
- Prevents duplicate businesses per user
- Validates and normalizes input
- Stores to database

**Update Business** (`src/services/business/update.ts`):
- Validates authenticated user
- Verifies business ownership
- Performs partial update
- Returns updated business

## Validation Rules

| Field | Required | Length Limit | Valid Format / Characters |  Normalization Applied |
|-------|----------|--------------|---------------------------|----------------------|
| Name | Yes | 1 - 255 | "Letters, numbers, spaces, hyphens, apostrophes, ampersands, periods, commas" | "Trimmed, extra spaces  |collapsed"
| Industry | No | 0 - 100 | Same as Name | "Trimmed, empty converted to  |null"
| Description | No | 0 - 2000 | Alphanumeric (newlines preserved) | "Trimmed, spaces normalized, empty converted to null" |
| Website | No | 0 - 2048 | "Valid URL (http, https, www)" | "Lowercased, protocol added if missing, trailing slashes removed" |

**Note**: Control characters, HTML tags, and undocumented special symbols are strictly invalid across all fields.

---

## API Endpoints

### Create Business
```http
POST /api/businesses
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Acme Corporation",
  "industry": "Technology",
  "description": "We make quality products",
  "website": "https://acme.com"
}
```
Response: `201 Created`
```json
{
  "id": "uuid",
  "userId": "user-uuid",
  "name": "Acme Corporation",
  "industry": "Technology",
  "description": "We make quality products",
  "website": "https://acme.com",
  "createdAt": "2026-03-25T10:00:00Z",
  "updatedAt": "2026-03-25T10:00:00Z"
}
```

### Update Business
```http
PATCH /api/businesses/me
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Updated Name",
  "website": "https://newsite.com"
}
```
Response: `200 OK`

### Error Responses
- `400 Bad Request`: Invalid input or validation error
- `401 Unauthorized`: Missing or invalid authentication
- `404 Not Found`: Business not found
- `409 Conflict`: Business already exists for this user

## Security Features

### Input Validation
- Zod schemas enforce structure and format
- Pattern matching prevents injection attacks
- Length limits prevent buffer overflow
- URL validation ensures valid domains

### Sanitization
- HTML/XML tag removal
- String trimming removes hidden characters
- URL normalization prevents spoofing
- Case normalization for consistency

### Error Handling
- No detailed error messages in production
- Proper HTTP status codes
- Separation of concerns (validation vs business logic)
- Logging for security monitoring

## Input & Output Examples

### Valid Inputs

```typescript
// Minimal create
{ name: "Test Corp" }

// Full create
{
  name: "Smith & Associates",
  industry: "Professional Services",
  description: "Multi-disciplinary firm\nServing clients globally",
  website: "https://smith-assoc.com"
}

// Partial update
{
  website: "https://newsite.com"
}
```

### Invalid Inputs

```typescript
// Missing required field
{ industry: "Tech" } // ❌ name required

// Invalid characters
{ name: "<script>alert('xss')</script>" } // ❌ invalid chars

// Exceeds max length
{ name: "a".repeat(256) } // ❌ name limit 255

// Invalid URL
{ website: "not a valid url!@#" } // ❌ invalid format
```

### Input Transformations

```typescript
Input:  { name: "  Acme  Corp  " }
Output: { name: "Acme Corp" }

Input:  { website: "EXAMPLE.COM/" }
Output: { website: "https://example.com" }

Input:  { industry: "" }
Output: { industry: null }
```

## Testing & Performance

The business service includes comprehensive validation tests to ensure reliability:

- **80+ unit tests** covering schemas and normalization
- **Edge cases** and security scenarios
- **Integration tests** for full API workflows
- **>95% code coverage** for business service

Execute test suite:
```bash
npm test -- tests/unit/services/business
```

## Performance Considerations

- Zod validation: ~1-5ms per request
- Normalization: <1ms per request
- Middleware validation: Cached for repeated patterns
- Database queries: Using parameterized queries (SQL injection safe)

## Debugging

To debug normalization or validation failures, enable the logger in the service:
```typescript
import { logger } from '../../utils/logger';

logger.debug('Business input:', { validatedInput });
logger.error('Validation failed:', { error });
```

## Extending the Service

Follow these steps to safely add new fields to the business service:
1. **Update the Validation Schema**:
   ```typescript
   newField: z
     .string()
     .max(100)
     .optional()
   ```

2. **Add the Normalization Utility**:
   ```typescript
   export function normalizeNewField(value: string): string {
     return value.trim().toLowerCase();
   }
   ```

3. **Update the Repository Types**:
   ```typescript
   export type CreateBusinessData = {
     userId: string;
     name: string;
     newField?: string;
   };
   ```

4. **Expand the Test Suite**

Ensure tests are written for the new schema rules, normalization behavior, and database insertion.

## Migration Notes

When applying these normalization rules to existing data:
- Run normalization on existing businesses
- Update invalid URLs to valid format
- Clean up whitespace in names and descriptions
- Null out empty strings

## References

- Issue: #119 - Implement Business Service Input Normalization
- Zod Documentation: https://zod.dev/
- Express Middleware: https://expressjs.com/guide/using-middleware.html
- NatSpec Style: https://docs.soliditylang.org/en/v0.8.20/natspec-format.html
