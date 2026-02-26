import { Request, Response } from "express";
import { businessRepository } from "../../repositories/business.js";

export async function updateBusiness(req: Request, res: Response) {
  const userId = req.user!.userId;
  const business = businessRepository.findByUserId(userId);
  if (!business) {
    return res.status(404).json({ error: "Business not found" });
  }
  const { name, industry, description, website } = req.body;
  const updated = businessRepository.update(business.id, {
    name,
    industry,
    description,
    website,
  });
  return res.status(200).json(updated);
}
