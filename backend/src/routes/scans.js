import express from 'express'
import {
    getScans,
    getScanById,
    createScan,
    updateScan,
    deleteScan,
    getScanFindings,
    getScanStats,
    stopScan,
    continueScan,
    cleanupStaleScans,
} from '../controllers/scanController.js'
import { protect } from '../middleware/auth.js'
import { scanLimiter } from '../middleware/rateLimiter.js'

const router = express.Router()

// All scan routes are protected
router.use(protect)

router.get('/', getScans)
router.get('/stats', getScanStats)
router.get('/:id', getScanById)
router.post('/', scanLimiter, createScan)
router.put('/:id', updateScan)
router.delete('/:id', deleteScan)
router.get('/:id/findings', getScanFindings)
router.post('/:id/stop', stopScan)
router.post('/:id/continue', continueScan)

export { cleanupStaleScans }
export default router
