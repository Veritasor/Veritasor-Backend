import { Router } from 'express';
import { requireAuth } from '../middleware/requireAuth.js';
import { createBusiness } from '../services/business/create.js';
import { updateBusiness } from '../services/business/update.js';
import { getMyBusiness, getBusinessById } from '../services/business/get.js';

const router = Router();

router.post('/', requireAuth, createBusiness);
router.get('/me', requireAuth, getMyBusiness);
router.patch('/me', requireAuth, updateBusiness);
router.get('/:id', getBusinessById);

export default router;