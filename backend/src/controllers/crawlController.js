/**
 * Crawl Controller — proxies to Python spider, saves graph to Supabase
 */
import supabase from '../config/supabase.js'

const PYTHON_BRIDGE = 'http://localhost:8000'


/* ── POST /api/crawl ──────────────────────────────────────────────────────── */
export const startCrawl = async (req, res, next) => {
    try {
        const { target_url, max_depth = 3, max_pages = 150, scan_id } = req.body
        if (!target_url) return res.status(400).json({ error: 'target_url is required' })

        // Use AbortController for timeout (native fetch doesn't support timeout option)
        const controller = new AbortController()
        const timeoutId = setTimeout(() => controller.abort(), 180_000) // 3 min

        let pyRes
        try {
            pyRes = await fetch(`${PYTHON_BRIDGE}/crawl`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_url, max_depth, max_pages }),
                signal: controller.signal,
            })
        } catch (fetchErr) {
            clearTimeout(timeoutId)
            if (fetchErr.name === 'AbortError') {
                return res.status(504).json({ error: 'Crawler timed out after 3 minutes' })
            }
            return res.status(503).json({
                error: 'Python scanner is not running. Start it with: cd scanner-core && python api_bridge.py',
                detail: fetchErr.message,
            })
        }
        clearTimeout(timeoutId)

        if (!pyRes.ok) {
            const txt = await pyRes.text()
            return res.status(502).json({ error: 'Python crawler failed', detail: txt })
        }

        const graph = await pyRes.json()

        // Persist graph to Supabase (upsert so re-crawling updates)
        const record = {
            target_url,
            scan_id: scan_id || null,
            nodes: graph.nodes,
            edges: graph.edges,
            forms: graph.forms,
            stats: graph.stats,
            crawled_at: new Date().toISOString(),
        }

        const { data, error } = await supabase
            .from('crawl_graphs')
            .insert(record)
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
