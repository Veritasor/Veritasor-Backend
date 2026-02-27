import express from 'express'
import cors from 'cors'
import { attestationsRouter } from './routes/attestations.js'
import { healthRouter } from './routes/health.js'

export const app = express()

app.use(cors())
app.use(express.json())

app.use('/api/health', healthRouter)
app.use('/api/attestations', attestationsRouter)
