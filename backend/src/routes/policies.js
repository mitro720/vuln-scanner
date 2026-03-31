import express from 'express'
import { getPolicies, createPolicy, updatePolicy, deletePolicy } from '../controllers/policyController.js'

const router = express.Router()

router.get('/', getPolicies)
router.post('/', createPolicy)
router.put('/:id', updatePolicy)
router.delete('/:id', deletePolicy)

export default router
