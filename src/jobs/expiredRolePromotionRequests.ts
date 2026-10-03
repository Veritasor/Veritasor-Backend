import { logger } from '../utils/logger.js'
import { sweepExpiredRequests } from '../repositories/rolePromotionRequestRepository.js'
import { runInstrumentedJob, type JobOutcome } from './jobRunner.js'

export const EXPIRED_ROLE_PROMOTION_REQUESTS_JOB_NAME = 'expired_role_promotion_requests'

export const expiredRolePromotionRequestsJob = async (): Promise<JobOutcome> => {
  return runInstrumentedJob(EXPIRED_ROLE_PROMOTION_REQUESTS_JOB_NAME, async () => {
    logger.info('Running expired role promotion requests sweeper job...')

    try {
      const count = await sweepExpiredRequests()
      if (count > 0) {
        logger.info(`Marked ${count} expired role promotion requests`)
      } else {
        logger.info('No expired role promotion requests to mark')
      }
      return { itemsProcessed: count, success: true }
    } catch (error) {
      logger.error('Error running expired role promotion requests job:', error)
      return { itemsProcessed: 0, success: false }
    }
  })
}
