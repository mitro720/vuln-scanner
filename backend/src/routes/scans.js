import express from 'express'
import {
    getScans,
    getScanById,
    createScan,
    updateScan,
    deleteScan,
    getScanFindings,
    getScanStats,
} from '../controllers/scanController.js'
import { scanLimiter } from '../middleware/rateLimiter.js'

const router = express.Router()

router.get('/', getScans)
router.get('/stats', getScanStats)
router.get('/:id', getScanById)
router.post('/', scanLimiter, createScan)
router.put('/:id', updateScan)
router.delete('/:id', deleteScan)
router.get('/:id/findings', getScanFindings)

export default router
