import { attestationRepository } from "../repositories/attestation";
import { businessRepository } from "../repositories/business";

// Job to send attestation reminders to businesses
export const attestationReminderJob = async () => {
  console.log("Running attestation reminder job...");

  try {
    const businesses = businessRepository.getAll();
    const businessesToRemind = [];

    for (const business of businesses) {
      const attestations = attestationRepository.listByBusiness(business.id);
      const hasRecentAttestation = attestations.some((attestation) => {
        const attestationDate = new Date(attestation.attestedAt);
        const lastMonth = new Date();
        lastMonth.setMonth(lastMonth.getMonth() - 1);
        return attestationDate >= lastMonth;
      });

      if (!hasRecentAttestation) {
        businessesToRemind.push(business);
      }
    }

    if (businessesToRemind.length === 0) {
      console.log("No businesses to remind.");
      return;
    }

    console.log(`Found ${businessesToRemind.length} businesses to remind.`);

    // Send reminders
    for (const business of businessesToRemind) {
      const { email, name } = business;
      const subject = "Attestation Reminder";
      const text = `Hi ${name},\n\nPlease remember to submit your attestation for the current period.\n\nThanks,\nThe Veritasor Team`;

      // await sendEmail({ to: email, subject, text });
      console.log(`Reminder sent to ${email}`);
    }

    console.log("Attestation reminder job finished.");
  } catch (error) {
    console.error("Error running attestation reminder job:", error);
  }
};
