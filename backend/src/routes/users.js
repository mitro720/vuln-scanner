import express from 'express'
import { getAllUsers, createUser, deleteUser, updateUserRole, updateUserStatus } from '../controllers/userController.js'
import { protect, authorize } from '../middleware/auth.js'

const router = express.Router()

// All user management routes require authentication and admin role
router.use(protect)
router.use(authorize('admin'))

router.get('/', getAllUsers)
router.post('/', createUser)
router.patch('/:id/role', updateUserRole)
router.patch('/:id/status', updateUserStatus)
router.delete('/:id', deleteUser)

export default router
