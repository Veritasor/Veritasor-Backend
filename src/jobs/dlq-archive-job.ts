import { DeadLetterQueue } from '../services/webhooks/deadLetterQueue';
import { Logger } from '../utils/logger';

const logger = new Logger('DLQ-Archive-Job');

/**
 * Run DLQ archive job
 * This should be scheduled to run daily via cron or scheduler
 */
export async function runDlqArchiveJob(): Promise<void> {
  logger.info('Running DLQ archive job...');

  try {
    const dlq = new DeadLetterQueue();
    const result = await dlq.archiveOldEntries();

    logger.info(`Archive job completed: ${result.archived} entries archived, ${result.failed} failed`);

    if (result.failed > 0) {
      logger.warn(`${result.failed} entries failed to archive`);
    }

    // Send notification if failure rate is high
    const failureRate = result.total > 0 ? result.failed / result.total : 0;
    if (failureRate > 0.1) {
      logger.error(`High failure rate: ${(failureRate * 100).toFixed(2)}%`);
      // Send alert
      await sendAlert('DLQ Archive Failure', `Failure rate: ${(failureRate * 100).toFixed(2)}%`);
    }
  } catch (error) {
    logger.error('DLQ archive job failed:', error);
    await sendAlert('DLQ Archive Job Failed', error.message);
    throw error;
  }
}

async function sendAlert(title: string, message: string): Promise<void> {
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;
  if (webhookUrl) {
    try {
      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: `*${title}*\n${message}`,
        }),
      });
    } catch (error) {
      logger.error('Failed to send alert:', error);
    }
  }
}

// Run if called directly
if (require.main === module) {
  runDlqArchiveJob()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}
