import { logger } from '../utils/logger.js'
import { sweepExpiredRequests } from '../repositories/rolePromotionRequestRepository.js'

export const expiredRolePromotionRequestsJob = async () => {
  logger.info('Running expired role promotion requests sweeper job...')

  try {
    const count = await sweepExpiredRequests()
    if (count > 0) {
      logger.info(`Marked ${count} expired role promotion requests`)
    } else {
      logger.info('No expired role promotion requests to mark')
    }
  } catch (error) {
    logger.error('Error running expired role promotion requests job:', error)
  }
}
