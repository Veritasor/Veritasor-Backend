# Implementation Plan: Integration Repository

## Overview

This plan implements a data access layer for managing third-party service integration records. The repository follows an in-memory implementation pattern (consistent with existing codebase patterns) with an async interface that's compatible with future database implementations. All operations use TypeScript for type safety and include comprehensive testing with both property-based and unit tests.

## Tasks

- [x] 1. Set up repository structure and type definitions
  - Create `src/repositories/integration.ts` file
  - Define `Integration` interface with all required fields (id, userId, provider, externalId, token, metadata, createdAt, updatedAt)
  - Define `CreateIntegrationData` interface for create operations
  - Define `UpdateIntegrationData` interface for update operations
  - Set up in-memory storage using Map data structure
  - _Requirements: 2.3, 5.1, 5.3, 5.4, 5.5, 6.3_

- [x] 2. Implement listByUserId function
  - [x] 2.1 Create listByUserId function with async signature
    - Accept userId parameter as string
    - Return Promise<Integration[]>
    - Filter in-memory storage by userId
    - Return empty array when no integrations found
    - _Requirements: 1.1, 1.2, 1.3_
  
  - [ ]* 2.2 Write property test for listByUserId
    - **Property 1: List Returns All and Only Matching Records**
    - **Validates: Requirements 1.2**
    - Use fast-check to generate random integration data
    - Verify all returned records match the target userId
    - Verify no records with different userId are returned

- [x] 3. Implement create function
  - [x] 3.1 Create create function with async signature
    - Accept CreateIntegrationData parameter
    - Generate unique UUID for id field
    - Set createdAt and updatedAt to current ISO timestamp
    - Store integration in Map with id as key
    - Return complete Integration object
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 5.1, 5.2, 5.3, 5.4, 5.5_
  
  - [ ]* 3.2 Write property test for create
    - **Property 2: Create-Retrieve Round Trip Preserves Data**
    - **Validates: Requirements 2.2, 2.4, 5.3, 5.4, 6.3**
    - Use fast-check to generate random integration data
    - Verify created record contains all input fields unchanged
    - Verify generated id and timestamps are present

- [x] 4. Implement update function
  - [x] 4.1 Create update function with async signature
    - Accept id and UpdateIntegrationData parameters
    - Return null if integration with id doesn't exist
    - Update only token and/or metadata fields provided
    - Update updatedAt timestamp to current time
    - Keep createdAt and other fields unchanged
    - Return updated Integration object
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
  
  - [ ]* 4.2 Write property test for update
    - **Property 3: Update Modifies Only Specified Fields**
    - **Validates: Requirements 3.2, 3.3, 3.4**
    - Use fast-check to generate update data
    - Verify only specified fields are modified
    - Verify immutable fields remain unchanged

- [x] 5. Implement deleteById function
  - [x] 5.1 Create deleteById function with async signature
    - Accept id parameter as string
    - Return true if integration was deleted
    - Return false if integration with id doesn't exist
    - Remove integration from Map storage
    - _Requirements: 4.1, 4.2, 4.3, 4.4_
  
  - [ ]* 5.2 Write property test for delete
    - **Property 4: Delete Removes Record and Returns Success**
    - **Validates: Requirements 4.2, 4.3**
    - Verify deleteById returns true for existing records
    - Verify deleted record no longer appears in listByUserId results

- [x] 6. Checkpoint - Ensure all core functions work
  - Ensure all tests pass, ask the user if questions arise.

- [ ]* 7. Write property test for non-existent ID operations
  - **Property 5: Operations on Non-Existent IDs Are Idempotent**
  - **Validates: Requirements 3.5, 4.4**
  - Use fast-check to generate random non-existent IDs
  - Verify update returns null for non-existent IDs
  - Verify deleteById returns false for non-existent IDs
  - Verify no existing records are modified

- [ ]* 8. Write unit tests for specific examples
  - [ ]* 8.1 Create unit test file at `tests/unit/repositories/integration.test.ts`
    - Set up test suite with vitest
    - Import repository functions
    - Create helper functions for test data generation
  
  - [ ]* 8.2 Write unit tests for create function
    - Test creating integration with Stripe provider
    - Test creating integration with Razorpay provider
    - Test creating integration with Shopify provider
    - Test creating integration with empty metadata object
    - Test creating integration with complex nested token structure
    - Verify generated id is valid UUID format
    - Verify timestamps are in ISO 8601 format
    - _Requirements: 2.2, 2.4, 5.1, 5.2, 5.3, 5.4_
  
  - [ ]* 8.3 Write unit tests for listByUserId function
    - Test listing integrations for user with multiple providers
    - Test listing integrations for user with no integrations (empty array)
    - Test that integrations from different users are not mixed
    - _Requirements: 1.2, 1.3_
  
  - [ ]* 8.4 Write unit tests for update function
    - Test updating only token field
    - Test updating only metadata field
    - Test updating both token and metadata
    - Test update with non-existent integration ID (returns null)
    - Verify updatedAt timestamp changes after update
    - Verify createdAt timestamp doesn't change after update
    - Verify immutable fields (userId, provider, externalId) don't change
    - _Requirements: 3.2, 3.3, 3.4, 3.5_
  
  - [ ]* 8.5 Write unit tests for deleteById function
    - Test deleting existing integration (returns true)
    - Test deleting non-existent integration (returns false)
    - Verify deleted integration no longer appears in list
    - Test deleting same ID twice (second call returns false)
    - _Requirements: 4.2, 4.3, 4.4_

- [x] 9. Export repository functions and types
  - Export all interfaces (Integration, CreateIntegrationData, UpdateIntegrationData)
  - Export all functions (listByUserId, create, update, deleteById)
  - Ensure clean public API for consumers
  - _Requirements: 1.1, 2.1, 3.1, 4.1_

- [x] 10. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The implementation uses in-memory storage (Map) following existing codebase patterns
- All functions use async signatures for future database compatibility
- Property-based tests use fast-check with minimum 100 iterations
- Unit tests provide concrete examples and edge case coverage
- Each task references specific requirements for traceability
