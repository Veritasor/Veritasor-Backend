import { Router } from 'express'
import { requireAuth } from '../../middleware/requireAuth.js'
import adminGraphqlRouter from '../admin.graphql.js'
import statsRouter from './stats.js'
import attestationsRouter from './attestations.js'
import usersRouter from './users.js'
import rolePromotionsRouter from './rolePromotions.js'
import auditLogsRouter from './auditLogs.js'
import webhooksRouter from './webhooks.js'

const adminRouter = Router()

// All routes here require authentication
adminRouter.use(requireAuth)
adminRouter.use(adminGraphqlRouter)

adminRouter.use(statsRouter)
adminRouter.use(attestationsRouter)
adminRouter.use(usersRouter)
adminRouter.use(rolePromotionsRouter)
adminRouter.use(auditLogsRouter)
adminRouter.use(webhooksRouter)

export default adminRouter
