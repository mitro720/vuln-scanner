import express from 'express'
import { chatWithAI } from '../controllers/chatController.js'
import { apiLimiter } from '../middleware/rateLimiter.js'

const router = express.Router()

router.post('/', apiLimiter, chatWithAI)

export default router
