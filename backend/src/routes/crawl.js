import { Router } from 'express'
import { startCrawl, getCrawl, getCrawlByScan, getCrawlHistory } from '../controllers/crawlController.js'

const router = Router()

router.post('/', startCrawl)
router.get('/history', getCrawlHistory)
router.get('/scan/:scan_id', getCrawlByScan)
router.get('/:id', getCrawl)

export default router
