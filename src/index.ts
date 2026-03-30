import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import { config } from './config/index.js'
import { errorHandler } from './middleware/errorHandler.js'
import { requestLogger } from './middleware/requestLogger.js'
import { analyticsRouter } from './routes/analytics.js'
import { authRouter } from './routes/auth.js'
import { attestationsRouter } from './routes/attestations.js'
import { healthRouter } from './routes/health.js'
import { integrationsShopifyRouter } from './routes/integrations-shopify.js'
import integrationsRazorpayRouter from './routes/integrations-razorpay.js'
import integrationsRouter from './routes/integrations.js'
import businessRoutes from './routes/businesses.js'
import { apiVersionMiddleware, versionResponseMiddleware } from './middleware/apiVersion.js'
import { attestationReminderJob } from './jobs/attestationReminder.js'

export const app = express()
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000

app.use(apiVersionMiddleware)
app.use(versionResponseMiddleware)
app.use(cors(config.cors))
app.use(express.json())
app.use(requestLogger)

app.use('/api/health', healthRouter)
app.use('/api/auth', authRouter)
app.use('/api/attestations', attestationsRouter)
app.use('/api/businesses', businessRoutes)
app.use('/api/analytics', analyticsRouter)
app.use('/api/integrations/shopify', integrationsShopifyRouter)
app.use('/api/integrations/razorpay', integrationsRazorpayRouter)
app.use('/api/integrations', integrationsRouter)

app.use(errorHandler);

if (process.env.NODE_ENV !== "test") {
  app.listen(PORT, () => {
    console.log(`Veritasor API listening on http://localhost:${PORT}`)
    // Run the job every minute
    setInterval(attestationReminderJob, 60 * 1000)
  })
}
