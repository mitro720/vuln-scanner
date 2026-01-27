import express from 'express'
import {
    getFindings,
    createFinding,
    getFindingById,
    updateFinding,
} from '../controllers/findingController.js'

const router = express.Router()

router.get('/', getFindings)
router.post('/', createFinding)
router.get('/:id', getFindingById)
router.put('/:id', updateFinding)

export default router
