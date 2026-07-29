# DLQ Archive with S3 Cold Storage

## Overview
The Dead Letter Queue (DLQ) archive system automatically ages out entries past TTL to S3 cold storage while keeping metadata queryable.

## Architecture

{
  "restoreToQueue": false
}
{
  "ttlDays": 30,
  "batchSize": 100
}
# Run DLQ tests
npm test -- deadLetterQueue.test.ts

# Run archive job test
npm test -- dlq-archive-job.test.ts

# Run with coverage
npm test -- --coverage
