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
import scanRoutes from './routes/scans.js'
import findingRoutes from './routes/findings.js'
import chatRoutes from './routes/chat.js'

dotenv.config()

const app = express()
const httpServer = createServer(app)
const io = new Server(httpServer, {
    cors: {
        origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:5173', 'http://localhost:5174'],
        methods: ['GET', 'POST'],
    },
})

const PORT = process.env.PORT || 3000

// Middleware
app.use(helmet())
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:5173', 'http://localhost:5174'],
    credentials: true,
}))
app.use(morgan('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

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

app.use('/api/scans', scanRoutes)
app.use('/api/findings', findingRoutes)
app.use('/api/chat', chatRoutes)

// Error handling
app.use(errorHandler)

// Setup WebSocket
export const wsHandlers = setupWebSocket(io)

// Start server
httpServer.listen(PORT, () => {
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
