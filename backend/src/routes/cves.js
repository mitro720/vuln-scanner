import express from 'express'
import {
    getCVEById,
    getServicesByScan,
    getCVEsByScan,
    lookupCVE,
    getCVEStats
} from '../controllers/cveController.js'

import { protect } from '../middleware/auth.js'

const router = express.Router()

router.use(protect)

// Get CVE by ID
router.get('/cves/:cveId', getCVEById)

// Get services for a scan
router.get('/scans/:scanId/services', getServicesByScan)

// Get CVEs for a scan
router.get('/scans/:scanId/cves', getCVEsByScan)

// Get CVE statistics for a scan
router.get('/scans/:scanId/cve-stats', getCVEStats)

// Manual CVE lookup
router.post('/cves/lookup', lookupCVE)

export default router
