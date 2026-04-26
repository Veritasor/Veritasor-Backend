import { businessRepository } from '../../repositories/business.js';
export async function getMyBusiness(req, res) {
    const userId = req.user.id;
    const business = await businessRepository.getByUserId(userId);
    if (!business) {
        return res.status(404).json({ error: 'Business not found' });
    }
    return res.status(200).json(business);
}
const PUBLIC_FIELDS = ['id', 'name', 'industry', 'description', 'website', 'createdAt'];
export async function getBusinessById(req, res) {
    const business = await businessRepository.getById(req.params.id);
    if (!business) {
        return res.status(404).json({ error: 'Business not found' });
    }
    const publicBusiness = Object.fromEntries(Object.entries(business).filter(([key]) => PUBLIC_FIELDS.includes(key)));
    return res.status(200).json(publicBusiness);
}
