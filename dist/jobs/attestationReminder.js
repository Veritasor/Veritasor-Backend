import { attestationRepository } from "../repositories/attestation.js";
import { businessRepository } from "../repositories/business.js";
// Job to send attestation reminders to businesses
export const attestationReminderJob = async () => {
    console.log("Running attestation reminder job...");
    try {
        const businesses = await businessRepository.getAll();
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
            const { name } = business;
            const subject = "Attestation Reminder";
            const text = `Hi ${name},\n\nPlease remember to submit your attestation for the current period.\n\nThanks,\nThe Veritasor Team`;
            // TODO: Fetch user email via business.userId and send email
            // await sendEmail({ to: user.email, subject, text });
            console.log(`Reminder would be sent for business: ${name}`);
        }
        console.log("Attestation reminder job finished.");
    }
    catch (error) {
        console.error("Error running attestation reminder job:", error);
    }
};
