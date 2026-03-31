import express from 'express'
import { aiChat, analyzeFinding, remediateFinding, testConnection, generateScanSummary } from '../controllers/aiController.js'

const router = express.Router()

router.post('/chat', aiChat)
router.post('/analyze', analyzeFinding)
router.post('/remediate', remediateFinding)
router.post('/summary', generateScanSummary)
router.post('/test', testConnection)

export default router
