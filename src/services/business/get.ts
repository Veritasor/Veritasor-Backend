import { Request, Response } from 'express';
import { businessRepository } from '../../repositories/business.js';

export async function getMyBusiness(req: Request, res: Response) {
  const userId = req.user!.id;
  const business = await businessRepository.getByUserId(userId);
  if (!business) {
    return res.status(404).json({ error: 'Business not found' });
  }
  return res.status(200).json(business);
}

const PUBLIC_FIELDS = ['id', 'name', 'industry', 'description', 'website', 'createdAt'] as const;

export async function getBusinessById(req: Request, res: Response) {
  const business = await businessRepository.getById(req.params.id);
  if (!business) {
    return res.status(404).json({ error: 'Business not found' });
  }
  const publicBusiness = Object.fromEntries(
    Object.entries(business).filter(([key]) => PUBLIC_FIELDS.includes(key as any))
  );
  return res.status(200).json(publicBusiness);
}

export async function listBusinesses(req: Request, res: Response) {
  const query = req.query as any;
  const result = await businessRepository.list({
    limit: query.limit,
    cursor: query.cursor,
    sortBy: query.sortBy,
    sortOrder: query.sortOrder,
    industry: query.industry,
  });

  // Filter public fields for each business
  const items = result.items.map(business => 
    Object.fromEntries(Object.entries(business).filter(([key]) => PUBLIC_FIELDS.includes(key as any)))
  );

  return res.status(200).json({
    items,
    nextCursor: result.nextCursor,
  });
}
