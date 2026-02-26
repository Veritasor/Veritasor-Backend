import { Request, Response } from 'express';
import { businessRepository } from '../../repositories/business.js';

export async function createBusiness(req: Request, res: Response) {
  const userId = req.user!.userId;
  const existing = businessRepository.findByUserId(userId);
  if (existing) {
    return res.status(409).json({ error: 'Business already exists for this user' });
  }
  const { name, industry, description, website } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'name is required' });
  }
  const business = businessRepository.create({ userId, name, industry, description, website });
  return res.status(201).json(business);
}