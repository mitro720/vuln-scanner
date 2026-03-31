import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import morgan from 'morgan'
import dotenv from 'dotenv'
import { createServer } from 'http'
import { Server } from 'socket.io'
import { errorHandler } from './middleware/errorHandler.js'
import { apiLimiter } from './middleware/rateLimiter.js'
import { setupWebSocket } from './websocket/scanSocket.js'
import scanRoutes, { cleanupStaleScans } from './routes/scans.js'
import findingRoutes from './routes/findings.js'
import chatRoutes from './routes/chat.js'
import cveRoutes from './routes/cves.js'
import aiRoutes from './routes/ai.js'
import scheduleRoutes from './routes/schedules.js'
import policyRoutes from './routes/policies.js'
import crawlRoutes from './routes/crawl.js'
import authRoutes from './routes/auth.js'
import userRoutes from './routes/users.js'
import { seedAdmin } from './controllers/authController.js'
import { initSchedules } from './controllers/scheduleController.js'

dotenv.config()

const app = express()
const httpServer = createServer(app)
const io = new Server(httpServer, {
    cors: {
        origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:5173', 'http://localhost:5174'],
        methods: ['GET', 'POST'],
    },
})

const PORT = process.env.PORT || 5001

// Middleware
app.use(helmet())
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:5173', 'http://localhost:5174'],
    credentials: true,
}))
app.use(morgan('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))

// Rate limiting
app.use('/api', apiLimiter)

// Routes
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'SecureScan API is running',
        timestamp: new Date().toISOString(),
    })
})

app.use('/api/auth', authRoutes)
app.use('/api/users', userRoutes)
app.use('/api/scans', scanRoutes)
app.use('/api/findings', findingRoutes)
app.use('/api/chat', chatRoutes)
app.use('/api', cveRoutes)
app.use('/api/ai', aiRoutes)
app.use('/api/schedules', scheduleRoutes)
app.use('/api/policies', policyRoutes)
app.use('/api/crawl', crawlRoutes)

// Error handling
app.use(errorHandler)

// Setup WebSocket
export const wsHandlers = setupWebSocket(io)

// Initialize scheduled scans and cleanup zombie scans from DB
initSchedules().catch(e => console.warn('Schedule init error:', e.message))
cleanupStaleScans().catch(e => console.warn('Cleanup error:', e.message))

httpServer.listen(PORT, () => {
    seedAdmin()
    console.log(`
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║   🔒 SecureScan API Server                           ║
║                                                       ║
║   Server running on: http://localhost:${PORT}        ║
║   Environment: ${process.env.NODE_ENV || 'development'}                      ║
║   WebSocket: Ready                                    ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
  `)
})

export default app
