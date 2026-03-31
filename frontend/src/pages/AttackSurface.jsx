import { useState, useEffect, useRef, useCallback } from 'react'
import * as d3 from 'd3'
import { Radar, Search, Loader2, Globe, AlertCircle, X, ExternalLink, ZoomIn, ZoomOut, RefreshCw, Target, Network, Layers, Layout } from 'lucide-react'
import { useNavigate, useSearchParams } from 'react-router-dom'

const API = 'http://localhost:5000/api'

/* ── node colour/icon by type ── */
const NODE_STYLE = {
    page: { color: '#818cf8', glow: '#818cf820', label: '📄 Page' },
    form: { color: '#f59e0b', glow: '#f59e0b20', label: '📝 Form' },
    api: { color: '#ef4444', glow: '#ef444420', label: '⚡ API' },
    static: { color: '#6b7280', glow: '#6b728020', label: '📦 Static' },
    external: { color: '#374151', glow: '#37415120', label: '🌐 External' },
    root: { color: '#22c55e', glow: '#22c55e30', label: '🏠 Root' },
}

const nodeStyle = (node) => node.is_root ? NODE_STYLE.root : (NODE_STYLE[node.type] || NODE_STYLE.page)

/* ── status code colour ── */
const statusColor = (code) => {
    if (!code || code === 0) return '#6b7280'
    if (code < 300) return '#22c55e'
    if (code < 400) return '#3b82f6'
    if (code < 500) return '#f59e0b'
    return '#ef4444'
}

/* ═══════════════════════════════════════════════════════════
   AttackSurface page
═══════════════════════════════════════════════════════════ */
const AttackSurface = () => {
    const navigate = useNavigate()
    const svgRef = useRef(null)
    const wrapRef = useRef(null)

    const [targetUrl, setTargetUrl] = useState('')
    const [maxDepth, setMaxDepth] = useState(2)
    const [maxPages, setMaxPages] = useState(100)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState(null)
    const [graph, setGraph] = useState(null)  // {nodes, edges, stats}
    const [selected, setSelected] = useState(null)  // clicked node
    const [filter, setFilter] = useState('all') // type filter
    const [viewMode, setViewMode] = useState('network') // 'network' | 'hierarchy'

    const [searchParams] = useSearchParams()
    const simulationRef = useRef(null)

    // Load graph from scan ID if provided
    useEffect(() => {
        const scanId = searchParams.get('scanId')
        if (!scanId) return

        const loadScanGraph = async () => {
            setLoading(true)
            try {
                const userData = JSON.parse(localStorage.getItem('user') || '{}');
                const token = userData?.token;
                const res = await fetch(`${API}/crawl/scan/${scanId}`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                })
                if (!res.ok) throw new Error('Failed to load crawl graph for this scan')
                const data = await res.json()
                const crawlRecord = data.data

                if (crawlRecord?.nodes?.length > 0) {
                    setTargetUrl(crawlRecord.target_url)
                    setGraph(crawlRecord)
                } else {
                    setError('This scan does not contain an attack surface graph yet.')
                }
            } catch (err) {
                setError(err.message)
            } finally {
                setLoading(false)
            }
        }

        loadScanGraph()
    }, [searchParams])

    /* ── crawl ─────────────────────────────────────────────── */
    const runCrawl = async (e) => {
        e?.preventDefault()
        if (!targetUrl.trim()) return
        setLoading(true); setError(null); setGraph(null); setSelected(null)
        try {
            const userData = JSON.parse(localStorage.getItem('user') || '{}');
            const token = userData?.token;
            const res = await fetch(`${API}/crawl`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ target_url: targetUrl.trim(), max_depth: maxDepth, max_pages: maxPages }),
            })
            if (!res.ok) throw new Error(`Server returned ${res.status}`)
            const data = await res.json()
            if (data.error) throw new Error(data.error)
            setGraph(data)
        } catch (err) {
            setError(err.message)
        } finally {
            setLoading(false)
        }
    }

    /* ── D3 render ─────────────────────────────────────────── */
    const renderGraph = useCallback(() => {
        if (!graph || !svgRef.current) return

        const container = wrapRef.current
        const W = container?.clientWidth || 900
        const H = container?.clientHeight || 600

        // Filter nodes
        const visibleNodes = filter === 'all'
            ? graph.nodes
            : graph.nodes.filter(n => n.type === filter || n.is_root)
        const visibleIds = new Set(visibleNodes.map(n => n.id))
        const visibleEdges = graph.edges.filter(e => visibleIds.has(e.source) && visibleIds.has(e.target))

        const svg = d3.select(svgRef.current)
            .attr('width', W).attr('height', H)

        // Stop any previous simulation or hierarchy zoom
        if (simulationRef.current) simulationRef.current.stop()
        svg.on('.zoom', null)

        // Zoom behaviour
        const g = svg.append('g')
        svg.call(d3.zoom().scaleExtent([0.15, 4]).on('zoom', (ev) => g.attr('transform', ev.transform)))

        // Arrow marker
        svg.append('defs').append('marker')
            .attr('id', 'arrow')
            .attr('viewBox', '0 -5 10 10').attr('refX', 18).attr('refY', 0)
            .attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
            .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#374151')

        // Nodes + edges (mutable copies for D3)
        const nodes = visibleNodes.map(n => ({ ...n }))
        const edges = visibleEdges.map(e => ({ ...e }))

        const simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(edges).id(d => d.id).distance(d => {
                // Root→child shorter, deep nodes further
                const depth = d.target.depth || 1
                return 60 + depth * 20
            }).strength(0.4))
            .force('charge', d3.forceManyBody().strength(-280))
            .force('center', d3.forceCenter(W / 2, H / 2))
            .force('collision', d3.forceCollide(22))

        simulationRef.current = simulation

        // Edges
        const link = g.append('g').selectAll('line')
            .data(edges).join('line')
            .attr('stroke', '#1f2937')
            .attr('stroke-width', 1.2)
            .attr('marker-end', 'url(#arrow)')

        // Node groups
        const node = g.append('g').selectAll('g')
            .data(nodes).join('g')
            .style('cursor', 'pointer')
            .call(d3.drag()
                .on('start', (ev, d) => { if (!ev.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
                .on('drag', (ev, d) => { d.fx = ev.x; d.fy = ev.y })
                .on('end', (ev, d) => { if (!ev.active) simulation.alphaTarget(0); d.fx = null; d.fy = null })
            )
            .on('click', (ev, d) => { ev.stopPropagation(); setSelected(d) })

        node.append('circle')
            .attr('r', d => d.is_root ? 16 : (d.type === 'api' ? 10 : 8))
            .attr('fill', d => nodeStyle(d).color)
            .attr('stroke', d => d.is_root ? '#22c55e' : '#111827')
            .attr('stroke-width', d => d.is_root ? 3 : 1.5)
            .style('filter', d => `drop-shadow(0 0 6px ${nodeStyle(d).glow})`)

        node.append('text')
            .text(d => {
                const p = new URL(d.url).pathname
                const parts = p.split('/').filter(Boolean)
                return parts[parts.length - 1]?.substring(0, 12) || '/'
            })
            .attr('x', 0).attr('y', d => (d.is_root ? 16 : 8) + 12)
            .attr('text-anchor', 'middle')
            .attr('font-size', 9).attr('fill', '#9ca3af')
            .style('pointer-events', 'none')

        simulation.on('tick', () => {
            link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x).attr('y2', d => d.target.y)
            node.attr('transform', d => `translate(${d.x},${d.y})`)
        })

        svg.on('click', () => setSelected(null))
    }, [graph, filter])

    /* ── D3 Hierarchy (Mind Map) render ────────────────────── */
    const renderHierarchy = useCallback(() => {
        if (!graph || !svgRef.current) return

        const container = wrapRef.current
        const W = container?.clientWidth || 900
        const H = container?.clientHeight || 600

        // Stop any active simulations from the network view
        if (simulationRef.current) simulationRef.current.stop()

        d3.select(svgRef.current).selectAll('*').remove()
        const svg = d3.select(svgRef.current).attr('width', W).attr('height', H)

        // Use a consistent zoom instance for hierarchy
        const zoom = d3.zoom().scaleExtent([0.15, 3]).on('zoom', (ev) => g.attr('transform', ev.transform))
        const g = svg.append('g')
        svg.call(zoom)

        // 1. Build tree structure from flat nodes/edges
        const nodesMap = new Map()
        graph.nodes.forEach(n => nodesMap.set(n.id, { ...n, children: [] }))

        const rootId = graph.nodes.find(n => n.is_root)?.id
        if (!rootId) return

        // Build adjacency list for BFS
        const adj = new Map()
        graph.edges.forEach(e => {
            if (!adj.has(e.source)) adj.set(e.source, [])
            adj.get(e.source).push(e.target)
        })

        // BFS to build a strict tree
        const visited = new Set([rootId])
        const queue = [rootId]

        while (queue.length > 0) {
            const currId = queue.shift()
            const parent = nodesMap.get(currId)
            const childrenIds = adj.get(currId) || []

            for (const childId of childrenIds) {
                if (!visited.has(childId)) {
                    visited.add(childId)
                    const child = nodesMap.get(childId)
                    if (child) {
                        parent.children.push(child)
                        queue.push(childId)
                    }
                }
            }
        }

        const root = d3.hierarchy(nodesMap.get(rootId))

        // 2. Compute tree layout
        const treeLayout = d3.tree().nodeSize([40, 200])
        treeLayout(root)

        // 3. Draw links
        g.append('g').selectAll('path')
            .data(root.links())
            .join('path')
            .attr('fill', 'none')
            .attr('stroke', '#1f2937')
            .attr('stroke-width', 1.5)
            .attr('d', d3.linkHorizontal().x(d => d.y).y(d => d.x))

        // 4. Draw nodes
        const node = g.append('g').selectAll('g')
            .data(root.descendants())
            .join('g')
            .attr('transform', d => `translate(${d.y},${d.x})`)
            .style('cursor', 'pointer')
            .on('click', (ev, d) => { ev.stopPropagation(); setSelected(d.data) })

        node.append('circle')
            .attr('r', d => d.data.is_root ? 8 : 5)
            .attr('fill', d => nodeStyle(d.data).color)
            .style('filter', d => `drop-shadow(0 0 5px ${nodeStyle(d.data).glow})`)

        node.append('text')
            .attr('dy', '0.31em')
            .attr('x', d => d.children ? -12 : 12)
            .attr('text-anchor', d => d.children ? 'end' : 'start')
            .text(d => {
                const p = new URL(d.data.url).pathname
                const parts = p.split('/').filter(Boolean)
                return parts[parts.length - 1] || '/'
            })
            .attr('font-size', 10)
            .attr('fill', '#9ca3af')
            .clone(true).lower()
            .attr('stroke', '#000')
            .attr('stroke-width', 3)

        // Center on root with a slight delay to ensure container dimensions are ready
        const initialTransform = d3.zoomIdentity.translate(80, H / 2).scale(0.8)
        svg.transition().duration(500).call(zoom.transform, initialTransform)
    }, [graph])

    useEffect(() => {
        if (viewMode === 'network') renderGraph()
        else renderHierarchy()
    }, [viewMode, renderGraph, renderHierarchy])

    /* ── zoom helpers ── */
    const zoomSvg = (factor) => {
        const svg = d3.select(svgRef.current)
        svg.transition().call(d3.zoom().scaleExtent([0.15, 4]).on('zoom', (ev) => svg.select('g').attr('transform', ev.transform)).scaleBy, factor)
    }

    const scanNode = async (url) => {
        try {
            const userData = JSON.parse(localStorage.getItem('user') || '{}');
            const token = userData?.token;
            const res = await fetch(`${API}/scans`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ target_url: url, scan_type: 'quick' }),
            })
            const data = await res.json()
            const scanId = data?.data?.id || data?.id
            if (scanId) navigate(`/scan/${scanId}`)
        } catch (e) { alert('Failed to start scan: ' + e.message) }
    }

    /* ── type counts for legend ── */
    const typeCounts = graph
        ? Object.fromEntries(Object.keys(NODE_STYLE).map(t => [t, graph.nodes.filter(n => (n.is_root && t === 'root') || (!n.is_root && n.type === t)).length]))
        : {}

    return (
        <div className="max-w-7xl mx-auto px-4 pb-10">
            {/* ── Header ── */}
            <div className="mb-6">
                <h1 className="text-3xl font-bold text-gradient flex items-center space-x-3">
                    <Radar size={28} /><span>Attack Surface Map</span>
                </h1>
                <p className="text-gray-400 text-sm mt-1">Spider a target site and explore the full URL graph — pages, forms, API endpoints, and JS files.</p>
            </div>

            {/* ── Crawl Form ── */}
            <form onSubmit={runCrawl} className="bg-gray-900 border border-gray-800 rounded-2xl p-5 mb-6">
                <div className="flex flex-col sm:flex-row gap-3">
                    <div className="flex-1 relative">
                        <Globe size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                        <input
                            type="url" required
                            value={targetUrl} onChange={e => setTargetUrl(e.target.value)}
                            placeholder="https://example.com"
                            className="w-full pl-9 pr-4 py-2.5 bg-gray-800 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-purple-500 text-sm"
                        />
                    </div>
                    <div className="flex items-center space-x-3">
                        <div className="flex flex-col items-center">
                            <label className="text-xs text-gray-500 mb-1">Depth</label>
                            <select value={maxDepth} onChange={e => setMaxDepth(Number(e.target.value))}
                                className="bg-gray-800 border border-gray-700 text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-purple-500">
                                {[1, 2, 3, 4].map(d => <option key={d} value={d}>{d}</option>)}
                            </select>
                        </div>
                        <div className="flex flex-col items-center">
                            <label className="text-xs text-gray-500 mb-1">Max pages</label>
                            <select value={maxPages} onChange={e => setMaxPages(Number(e.target.value))}
                                className="bg-gray-800 border border-gray-700 text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-purple-500">
                                {[50, 100, 150, 200].map(d => <option key={d} value={d}>{d}</option>)}
                            </select>
                        </div>
                        <button type="submit" disabled={loading}
                            className="flex items-center space-x-2 px-5 py-2.5 gradient-bg text-white rounded-xl hover:shadow-lg hover:shadow-purple-500/20 transition-all text-sm font-semibold mt-4 disabled:opacity-60">
                            {loading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
                            <span>{loading ? 'Crawling…' : 'Crawl'}</span>
                        </button>
                    </div>
                </div>
            </form>

            {/* ── Error ── */}
            {error && (
                <div className="bg-red-900/20 border border-red-500/30 rounded-xl p-4 mb-6 flex items-center space-x-3 text-red-400">
                    <AlertCircle size={16} />
                    <span className="text-sm">{error}</span>
                </div>
            )}

            {/* ── Loading overlay ── */}
            {loading && (
                <div className="bg-gray-900 border border-gray-800 rounded-2xl p-16 flex flex-col items-center justify-center mb-6">
                    <div className="relative mb-6">
                        <div className="w-20 h-20 rounded-full border-4 border-purple-500/20 border-t-purple-500 animate-spin" />
                        <Radar className="absolute inset-0 m-auto text-purple-400" size={28} />
                    </div>
                    <p className="text-white font-semibold text-lg">Spidering…</p>
                    <p className="text-gray-400 text-sm mt-2">Following links up to depth {maxDepth} · max {maxPages} pages</p>
                    <p className="text-gray-600 text-xs mt-4">This may take 15–60 seconds for large sites</p>
                </div>
            )}

            {/* ── Graph area ── */}
            {graph && !loading && (
                <>
                    {/* Stats bar */}
                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-4">
                        {[
                            { label: 'Total nodes', value: graph.stats.total_nodes, color: '#818cf8' },
                            { label: 'Edges', value: graph.stats.total_edges, color: '#6b7280' },
                            { label: 'Forms', value: graph.stats.total_forms, color: '#f59e0b' },
                            { label: 'API routes', value: graph.stats.api || 0, color: '#ef4444' },
                            { label: 'Crawl time', value: `${graph.stats.elapsed_seconds}s`, color: '#22c55e' },
                        ].map(s => (
                            <div key={s.label} className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3 text-center">
                                <div className="text-2xl font-bold" style={{ color: s.color }}>{s.value}</div>
                                <div className="text-xs text-gray-500 mt-0.5">{s.label}</div>
                            </div>
                        ))}
                    </div>

                    {/* View mode + filters */}
                    <div className="flex flex-wrap items-center gap-2 mb-4">
                        {/* View Mode Toggle */}
                        <div className="flex bg-gray-900 border border-gray-800 rounded-lg p-1 mr-4">
                            <button onClick={() => setViewMode('network')}
                                className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${viewMode === 'network' ? 'bg-purple-600 text-white shadow-lg' : 'text-gray-400 hover:text-gray-300'}`}>
                                <Network size={14} /><span>Network Map</span>
                            </button>
                            <button onClick={() => setViewMode('hierarchy')}
                                className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${viewMode === 'hierarchy' ? 'bg-purple-600 text-white shadow-lg' : 'text-gray-400 hover:text-gray-300'}`}>
                                <Layers size={14} /><span>Hierarchical Mind Map</span>
                            </button>
                        </div>

                        {viewMode === 'network' && [['all', '🌐 All', '#818cf8'], ...Object.entries(NODE_STYLE).map(([k, v]) => [k, v.label, v.color])].map(([type, label, color]) => (
                            <button key={type}
                                onClick={() => setFilter(type)}
                                className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${filter === type ? 'border-opacity-100 text-white' : 'border-gray-700 text-gray-400 hover:border-gray-600'}`}
                                style={filter === type ? { borderColor: color, background: color + '22', color } : {}}>
                                {label} {type !== 'all' && typeCounts[type] ? `(${typeCounts[type]})` : ''}
                            </button>
                        ))}
                        <div className="ml-auto flex items-center space-x-2">
                            <button onClick={() => zoomSvg(1.3)} className="p-1.5 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors text-gray-300"><ZoomIn size={14} /></button>
                            <button onClick={() => zoomSvg(0.77)} className="p-1.5 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors text-gray-300"><ZoomOut size={14} /></button>
                            <button onClick={runCrawl} className="p-1.5 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors text-gray-300"><RefreshCw size={14} /></button>
                        </div>
                    </div>

                    {/* Graph canvas + inspector */}
                    <div className="flex gap-4">
                        {/* SVG */}
                        <div ref={wrapRef} className="flex-1 bg-gray-950 border border-gray-800 rounded-2xl overflow-hidden relative"
                            style={{ height: '60vh', minHeight: 480 }}>
                            <svg ref={svgRef} className="w-full h-full" />
                            {/* Legend */}
                            <div className="absolute bottom-4 left-4 bg-gray-900/90 backdrop-blur rounded-xl border border-gray-800 p-3 space-y-1.5">
                                {Object.entries(NODE_STYLE).map(([t, s]) => (
                                    <div key={t} className="flex items-center space-x-2">
                                        <div className="w-2.5 h-2.5 rounded-full" style={{ background: s.color }} />
                                        <span className="text-xs text-gray-400">{s.label}</span>
                                    </div>
                                ))}
                            </div>
                            <div className="absolute top-3 right-3 text-xs text-gray-600">Drag · Scroll to zoom · Click node to inspect</div>
                        </div>

                        {/* Node Inspector Panel */}
                        {selected && (
                            <div className="w-80 bg-gray-900 border border-gray-800 rounded-2xl overflow-hidden flex-shrink-0">
                                {/* Panel header */}
                                <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between"
                                    style={{ background: nodeStyle(selected).color + '15' }}>
                                    <div className="flex items-center space-x-2">
                                        <div className="w-3 h-3 rounded-full" style={{ background: nodeStyle(selected).color }} />
                                        <span className="text-sm font-semibold text-white capitalize">{selected.is_root ? 'Root' : selected.type}</span>
                                    </div>
                                    <div className="flex items-center space-x-2">
                                        <span className="text-xs px-2 py-0.5 rounded font-mono" style={{ background: statusColor(selected.status_code) + '22', color: statusColor(selected.status_code) }}>
                                            HTTP {selected.status_code || '–'}
                                        </span>
                                        <button onClick={() => setSelected(null)} className="text-gray-500 hover:text-gray-300"><X size={14} /></button>
                                    </div>
                                </div>

                                <div className="p-4 space-y-4 overflow-y-auto" style={{ maxHeight: '55vh' }}>
                                    {/* URL */}
                                    <div>
                                        <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">URL</p>
                                        <p className="text-white text-xs font-mono break-all bg-gray-800 rounded-lg p-2">{selected.url}</p>
                                        <div className="flex items-center space-x-2 mt-2">
                                            <a href={selected.url} target="_blank" rel="noopener noreferrer"
                                                className="flex items-center space-x-1 text-xs text-blue-400 hover:text-blue-300">
                                                <ExternalLink size={11} /><span>Open</span>
                                            </a>
                                        </div>
                                    </div>

                                    {/* Meta */}
                                    <div className="grid grid-cols-2 gap-2">
                                        <div className="bg-gray-800 rounded-lg p-2 text-center">
                                            <div className="text-lg font-bold text-white">{selected.depth}</div>
                                            <div className="text-xs text-gray-500">Depth</div>
                                        </div>
                                        <div className="bg-gray-800 rounded-lg p-2 text-center">
                                            <div className="text-lg font-bold" style={{ color: statusColor(selected.status_code) }}>{selected.status_code || '–'}</div>
                                            <div className="text-xs text-gray-500">HTTP Status</div>
                                        </div>
                                    </div>

                                    {/* Title */}
                                    {selected.title && (
                                        <div>
                                            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Page Title</p>
                                            <p className="text-white text-sm">{selected.title}</p>
                                        </div>
                                    )}

                                    {/* Forms on this URL */}
                                    {(() => {
                                        const nodeForms = (graph.forms || []).filter(f => f.page_url === selected.url || f.action === selected.url)
                                        return nodeForms.length > 0 ? (
                                            <div>
                                                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Forms ({nodeForms.length})</p>
                                                {nodeForms.map((f, i) => (
                                                    <div key={i} className="bg-gray-800 rounded-lg p-3 mb-2">
                                                        <div className="flex items-center justify-between mb-1">
                                                            <span className="text-xs font-semibold text-yellow-400">{f.method}</span>
                                                            <span className="text-xs text-gray-500">{f.inputs?.length || 0} fields</span>
                                                        </div>
                                                        <p className="text-xs text-gray-400 font-mono break-all">{f.action}</p>
                                                        {f.inputs?.filter(inp => inp.name).slice(0, 4).map((inp, j) => (
                                                            <div key={j} className="text-xs text-gray-500 mt-1">
                                                                <span className="text-purple-400">{inp.name}</span>
                                                                {inp.type !== 'text' && <span className="ml-1 text-gray-600">({inp.type})</span>}
                                                                {inp.required && <span className="ml-1 text-red-500">*</span>}
                                                            </div>
                                                        ))}
                                                    </div>
                                                ))}
                                            </div>
                                        ) : null
                                    })()}

                                    {/* Actions */}
                                    <div className="space-y-2 pt-2 border-t border-gray-800">
                                        <button
                                            onClick={() => scanNode(selected.url)}
                                            className="w-full flex items-center justify-center space-x-2 px-4 py-2.5 gradient-bg text-white rounded-xl hover:shadow-lg hover:shadow-purple-500/20 text-sm font-semibold transition-all">
                                            <Target size={14} /><span>Scan this URL</span>
                                        </button>
                                        <button
                                            onClick={() => window.__securescanAI?.openWithFinding({ name: selected.type + ' endpoint', url: selected.url, severity: 'Info', description: `Discovered endpoint: ${selected.url}` })}
                                            className="w-full flex items-center justify-center space-x-2 px-4 py-2 bg-gray-800 border border-gray-700 text-gray-300 rounded-xl hover:bg-gray-700 text-sm transition-all">
                                            <span>🤖 Ask AI about this</span>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                </>
            )}

            {/* Empty state */}
            {!graph && !loading && !error && (
                <div className="bg-gray-900 border border-gray-800 border-dashed rounded-2xl p-16 text-center">
                    <Radar size={48} className="mx-auto text-gray-700 mb-4" />
                    <h3 className="text-xl font-semibold text-gray-400 mb-2">No map yet</h3>
                    <p className="text-gray-600 text-sm">Enter a URL above and click <strong className="text-purple-400">Crawl</strong> to spider the site and visualize the attack surface.</p>
                </div>
            )}
        </div>
    )
}

export default AttackSurface
