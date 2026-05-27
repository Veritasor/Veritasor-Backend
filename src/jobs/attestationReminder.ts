import { attestationRepository } from "../repositories/attestation.js";
import { businessRepository } from "../repositories/business.js";
import { Attestation } from "../repositories/attestation.js";
import { logger } from "../utils/logger.js";

/**
 * Job to send attestation reminders to businesses that have not submitted
 * an attestation within the past month threshold.
 */
export const attestationReminderJob = async () => {
  logger.info("Running attestation reminder job...");

  try {
    const businesses = await businessRepository.getAll();
    const businessesToRemind = [];

    for (const business of businesses) {
      // FIX: Added missing await for repository method invocation
      const attestations = await attestationRepository.listByBusiness(business.id);
      
      const hasRecentAttestation = attestations.some(
        (attestation: Attestation) => {
          const attestationDate = new Date(attestation.attestedAt);
          const lastMonth = new Date();
          lastMonth.setMonth(lastMonth.getMonth() - 1);
          return attestationDate >= lastMonth;
        },
      );

      if (!hasRecentAttestation) {
        businessesToRemind.push(business);
      }
    }

    if (businessesToRemind.length === 0) {
      logger.info("No businesses to remind.");
      return;
    }

    logger.info(`Found ${businessesToRemind.length} businesses to remind.`);

    // Send reminders
    for (const business of businessesToRemind) {
      const { name } = business;
      // Logging routed safely through structural utilities
      logger.info(`Reminder would be sent for business: ${name}`);
    }

    logger.info("Attestation reminder job finished.");
  } catch (error) {
    logger.error("Error running attestation reminder job:", error);
  }
};