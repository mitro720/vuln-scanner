import express from 'express'
import {
    getFindings,
    createFinding,
    getFindingById,
    updateFinding,
    updateFindingStatus,
} from '../controllers/findingController.js'

import { protect } from '../middleware/auth.js'

const router = express.Router()

// GET requests are protected
router.get('/', protect, getFindings)
router.get('/:id', protect, getFindingById)

// POST finding (internal from scanner)
router.post('/', protect, createFinding)

// Status and remediation (user updates)
router.put('/:id', protect, updateFinding)
router.patch('/:id/status', protect, updateFindingStatus)

export default router

