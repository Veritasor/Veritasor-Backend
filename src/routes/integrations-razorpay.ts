import { Router } from 'express'
import { requireBusinessAuth } from '../middleware/requireBusinessAuth.js'
import connectRazorpay from '../services/integrations/razorpay/connect.js'
import disconnectRazorpay from '../services/integrations/razorpay/disconnect.js'

export const integrationsRazorpayRouter = Router()

// POST /api/integrations/razorpay - connect (API key flow)
integrationsRazorpayRouter.post('/', requireBusinessAuth, connectRazorpay)

// DELETE /api/integrations/razorpay - disconnect
integrationsRazorpayRouter.delete('/', requireBusinessAuth, disconnectRazorpay)

export default integrationsRazorpayRouter
