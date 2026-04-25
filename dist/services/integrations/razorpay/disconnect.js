import { integrationRepository } from '../../../repositories/integrations.js';
/**
 * Disconnect a previously connected Razorpay integration.
 * Expects { id } in the JSON body where id is the integration record id.
 */
export async function disconnectRazorpay(req, res) {
    const userId = req.user?.userId;
    if (!userId)
        return res.status(401).json({ error: 'Unauthorized' });
    const { id } = req.body ?? {};
    if (!id)
        return res.status(400).json({ error: 'id is required' });
    const rec = integrationRepository.findById(id);
    if (!rec || rec.provider !== 'razorpay' || rec.userId !== userId) {
        return res.status(404).json({ error: 'Integration not found' });
    }
    const ok = integrationRepository.deleteById(id);
    if (!ok)
        return res.status(500).json({ error: 'Failed to delete integration' });
    return res.json({ message: 'ok' });
}
export default disconnectRazorpay;
