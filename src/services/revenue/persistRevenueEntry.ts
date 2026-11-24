/**
 * Testable handler for normalized Kafka revenue entries.
 *
 * Persistence is keyed on (source, id), so redelivery is a no-op. The handler
 * counts inserted, duplicate and failed outcomes and rethrows failures so the
 * consumer can route the message to its DLT.
 */

import { revenueEntryRepository } from '../../repositories/revenueEntryRepository.js'
import { kafkaRevenueEntriesTotal } from '../../metrics.js'
import { logger } from '../../utils/logger.js'
import type { NormalizedRevenue } from './normalize.js'

export async function persistRevenueEntry(entry: NormalizedRevenue): Promise<void> {
  try {
    const result = await revenueEntryRepository.upsert(entry)
    kafkaRevenueEntriesTotal.inc({
      outcome: result.inserted ? 'inserted' : 'duplicate',
    })
    logger.info({
      event: 'kafka_revenue_entry_persisted',
      id: entry.id,
      source: entry.source,
      inserted: result.inserted,
    })
  } catch (error) {
    kafkaRevenueEntriesTotal.inc({ outcome: 'failed' })
    logger.error({
      event: 'kafka_revenue_entry_persist_failed',
      id: entry.id,
      source: entry.source,
      error: error instanceof Error ? error.message : String(error),
    })
    throw error
  }
}
