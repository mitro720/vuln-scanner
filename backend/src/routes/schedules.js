import express from 'express'
import { getSchedules, createSchedule, toggleSchedule, deleteSchedule } from '../controllers/scheduleController.js'

const router = express.Router()

router.get('/', getSchedules)
router.post('/', createSchedule)
router.patch('/:id/toggle', toggleSchedule)
router.delete('/:id', deleteSchedule)

export default router
