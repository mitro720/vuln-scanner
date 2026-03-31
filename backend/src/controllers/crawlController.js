/**
 * Crawl Controller — proxies to Python spider, saves graph to Supabase
 */
import supabase from '../config/supabase.js'

const PYTHON_BRIDGE = process.env.SCANNER_API_URL || 'http://localhost:8000'

const isUUID = (str) => {
    const regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    return regex.test(str)
}

/* ── POST /api/crawl ──────────────────────────────────────────────────────── */
export const startCrawl = async (req, res, next) => {
    try {
        const { target_url, max_depth = 3, max_pages = 150 } = req.body
        let { scan_id } = req.body
        
        if (!target_url) return res.status(400).json({ error: 'target_url is required' })

        // Validate UUID to prevent DB crashes (e.g. crawl-fix-v-final)
        if (scan_id && !isUUID(scan_id)) {
            console.warn('⚠️  Invalid UUID for scan_id received:', scan_id)
            scan_id = null 
        }

        // Check if data is already provided (from scanner bridge)
        let graph = req.body.nodes ? req.body : null

        if (!graph) {
            // Initiate a new crawl via Python bridge
            const controller = new AbortController()
            const timeoutId = setTimeout(() => controller.abort(), 180_000) // 3 min

            try {
                const pyRes = await fetch(`${PYTHON_BRIDGE}/crawl`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target_url, max_depth, max_pages }),
                    signal: controller.signal,
                })

                if (!pyRes.ok) {
                    const txt = await pyRes.text()
                    clearTimeout(timeoutId)
                    return res.status(502).json({ error: 'Python crawler failed', detail: txt })
                }
                graph = await pyRes.json()
            } catch (fetchErr) {
                if (fetchErr.name === 'AbortError') throw new Error('Crawler timed out after 3 minutes')
                throw fetchErr
            } finally {
                clearTimeout(timeoutId)
            }
        }

        // Persist graph to Supabase
        const record = {
            target_url,
            scan_id: scan_id || null,
            nodes: graph.nodes,
            edges: graph.edges,
            forms: graph.forms,
            stats: graph.stats,
            crawled_at: new Date().toISOString(),
        }

        let query = supabase.from('crawl_graphs')
        if (scan_id) {
            // Update existing or insert new
            query = query.upsert(record, { onConflict: 'scan_id' })
        } else {
            query = query.insert(record)
        }

        const { data, error } = await query
            .select('id')
            .single()

        if (error) console.warn('⚠️  Could not save crawl graph:', error.message)

        return res.json({
            success: true,
            crawl_id: data?.id || null,
            ...graph,
        })
    } catch (err) {
        next(err)
    }
}



/* ── GET /api/crawl/:id ───────────────────────────────────────────────────── */
export const getCrawl = async (req, res, next) => {
    try {
        const { id } = req.params
        const { data, error } = await supabase
            .from('crawl_graphs')
            .select('*')
            .eq('id', id)
            .single()

        if (error || !data) return res.status(404).json({ error: 'Crawl not found' })
        return res.json({ success: true, data })
    } catch (err) {
        next(err)
    }
}

/* ── GET /api/crawl/scan/:scan_id ─────────────────────────────────────────── */
export const getCrawlByScan = async (req, res, next) => {
    try {
        const { scan_id } = req.params
        const { data, error } = await supabase
            .from('crawl_graphs')
            .select('*')
            .eq('scan_id', scan_id)
            .order('crawled_at', { ascending: false })
            .limit(1)
            .single()

        if (error || !data) return res.json({ success: true, data: null })
        return res.json({ success: true, data })
    } catch (err) {
        next(err)
    }
}

/* ── GET /api/crawl/history?target_url=... ───────────────────────────────── */
export const getCrawlHistory = async (req, res, next) => {
    try {
        const { target_url } = req.query
        let q = supabase.from('crawl_graphs').select('id, target_url, stats, crawled_at').order('crawled_at', { ascending: false }).limit(20)
        if (target_url) q = q.ilike('target_url', `%${target_url}%`)
        const { data, error } = await q
        if (error) return res.status(500).json({ error: error.message })
        return res.json({ success: true, data: data || [] })
    } catch (err) {
        next(err)
    }
}
