import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import connectRazorpay from '../services/integrations/razorpay/connect.js';
import disconnectRazorpay from '../services/integrations/razorpay/disconnect.js';
export const integrationsRazorpayRouter = Router();
// POST /api/integrations/razorpay - connect (API key flow)
integrationsRazorpayRouter.post('/', requireAuth, connectRazorpay);
// DELETE /api/integrations/razorpay - disconnect
integrationsRazorpayRouter.delete('/', requireAuth, disconnectRazorpay);
export default integrationsRazorpayRouter;
