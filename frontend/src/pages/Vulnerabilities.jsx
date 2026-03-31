import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import SeverityBadge from '../components/common/SeverityBadge'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { Bug, Filter, Search, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react'

const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 }
const SEVERITY_COLORS = {
    Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#3b82f6', Info: '#8b5cf6'
}

const Vulnerabilities = () => {
    const [findings, setFindings] = useState([])
    const [scans, setScans] = useState([])
    const [loading, setLoading] = useState(true)
    const [searchQuery, setSearchQuery] = useState('')
    const [filterSeverity, setFilterSeverity] = useState('All')
    const [expandedGroups, setExpandedGroups] = useState({})
    const [viewMode, setViewMode] = useState('grouped') // 'grouped' | 'flat'
    const [sortBy, setSortBy] = useState('severity')

    useEffect(() => {
        const load = async () => {
            try {
                const scansRes = await fetch('http://localhost:5000/api/scans')
                if (!scansRes.ok) return
                const scansData = await scansRes.json()
                const arr = scansData.data || []
                setScans(arr)

                const token = JSON.parse(localStorage.getItem('user') || '{}')?.token
                const headers = { 'Authorization': `Bearer ${token}` }

                // Fetch findings from all scans (up to last 10)
                const allFindings = []
                await Promise.all(
                    arr.slice(0, 10).map(async (scan) => {
                        try {
                            const r = await fetch(`http://localhost:5000/api/scans/${scan.id}/findings`, { headers })
                            if (r.ok) {
                                const d = await r.json()
                                const fs = (d.data || d || []).map(f => ({ ...f, scan_target: scan.target_url, scan_id: scan.id }))
                                allFindings.push(...fs)
                            }
                        } catch { /* skip */ }
                    })
                )
                setFindings(allFindings)
            } catch (err) {
                console.error(err)
            } finally {
                setLoading(false)
            }
        }
        load()
        const interval = setInterval(load, 5000)
        return () => clearInterval(interval)
    }, [])

    // Filter
    const filtered = findings.filter(f => {
        const matchesSev = filterSeverity === 'All' || f.severity === filterSeverity
        const matchesQ = !searchQuery || f.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
            f.owasp?.toLowerCase().includes(searchQuery.toLowerCase()) ||
            f.scan_target?.toLowerCase().includes(searchQuery.toLowerCase())
        return matchesSev && matchesQ
    })

    // Sort
    const sorted = [...filtered].sort((a, b) => {
        if (sortBy === 'severity') return (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
        if (sortBy === 'cvss') return (b.cvss_score || 0) - (a.cvss_score || 0)
        return a.name?.localeCompare(b.name)
    })

    // Group by vulnerability name
    const grouped = sorted.reduce((acc, f) => {
        const key = f.name || 'Unknown'
        if (!acc[key]) acc[key] = { severity: f.severity, owasp: f.owasp, cwe: f.cwe, items: [] }
        acc[key].items.push(f)
        return acc
    }, {})

    // Stats for bar chart
    const severityStats = ['Critical', 'High', 'Medium', 'Low', 'Info'].map(s => ({
        name: s,
        count: findings.filter(f => f.severity === s).length,
        fill: SEVERITY_COLORS[s],
    }))

    const toggleGroup = (key) => setExpandedGroups(prev => ({ ...prev, [key]: !prev[key] }))

    return (
        <div className="max-w-7xl mx-auto px-4 pb-10">
            {/* Header */}
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-4xl font-bold text-gradient">Vulnerabilities</h1>
                    <p className="text-gray-400 mt-1">{findings.length} total findings across {scans.length} scans</p>
                </div>
                <div className="flex items-center space-x-3">
                    <button onClick={() => setViewMode(viewMode === 'grouped' ? 'flat' : 'grouped')}
                        className="px-4 py-2 bg-gray-800 text-gray-300 rounded-lg hover:bg-gray-700 text-sm font-medium border border-gray-700">
                        {viewMode === 'grouped' ? 'Flat View' : 'Grouped View'}
                    </button>
                </div>
            </div>

            {/* Severity Chart Bar */}
            {!loading && findings.length > 0 && (
                <div className="bg-gray-900 rounded-xl p-6 border border-gray-800 mb-6">
                    <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Severity Overview</h3>
                    <ResponsiveContainer width="100%" height={120}>
                        <BarChart data={severityStats} margin={{ top: 0, right: 10, left: -20, bottom: 0 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
                            <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                            <YAxis tick={{ fill: '#9ca3af', fontSize: 12 }} />
                            <Tooltip
                                cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                                contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }}
                            />
                            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                                {severityStats.map((entry, i) => (
                                    <Cell key={i} fill={entry.fill} />
                                ))}
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                    <div className="grid grid-cols-5 gap-2 mt-3">
                        {severityStats.map(s => (
                            <div key={s.name} className="text-center cursor-pointer" onClick={() => setFilterSeverity(filterSeverity === s.name ? 'All' : s.name)}>
                                <div className="text-2xl font-bold" style={{ color: s.fill }}>{s.count}</div>
                                <div className="text-xs text-gray-500">{s.name}</div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Filters */}
            <div className="flex flex-wrap items-center gap-3 mb-5">
                <div className="relative flex-1 min-w-[200px]">
                    <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                    <input
                        type="text"
                        placeholder="Search vulnerabilities..."
                        value={searchQuery}
                        onChange={e => setSearchQuery(e.target.value)}
                        className="w-full pl-9 pr-4 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:ring-1 focus:ring-purple-500 outline-none"
                    />
                </div>

                <div className="flex items-center space-x-2">
                    <Filter size={14} className="text-gray-500" />
                    {['All', 'Critical', 'High', 'Medium', 'Low', 'Info'].map(s => (
                        <button key={s}
                            onClick={() => setFilterSeverity(s)}
                            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${filterSeverity === s ? 'gradient-bg text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}>
                            {s}
                        </button>
                    ))}
                </div>

                <select value={sortBy} onChange={e => setSortBy(e.target.value)}
                    className="px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-300 outline-none focus:ring-1 focus:ring-purple-500">
                    <option value="severity">Sort: Severity</option>
                    <option value="cvss">Sort: CVSS Score</option>
                    <option value="name">Sort: Name</option>
                </select>
            </div>

            {loading ? (
                <div className="text-center py-16 text-gray-500">Loading findings...</div>
            ) : filtered.length === 0 ? (
                <div className="bg-gray-900 rounded-xl border border-gray-800 p-16 text-center">
                    <Bug size={48} className="mx-auto mb-4 text-gray-700" />
                    <p className="text-gray-400">No vulnerabilities found {searchQuery ? 'matching your search' : 'yet'}.</p>
                    {!searchQuery && <Link to="/scan/new" className="mt-4 inline-block text-purple-400 hover:text-purple-300 text-sm">Start a scan →</Link>}
                </div>
            ) : viewMode === 'grouped' ? (
                /* Grouped View (Nessus Plugin-style) */
                <div className="space-y-2">
                    {Object.entries(grouped).map(([name, group]) => (
                        <div key={name} className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
                            <button
                                onClick={() => toggleGroup(name)}
                                className="w-full flex items-center justify-between px-5 py-4 hover:bg-gray-800/50 transition-colors"
                            >
                                <div className="flex items-center space-x-4">
                                    {expandedGroups[name]
                                        ? <ChevronDown size={16} className="text-gray-500" />
                                        : <ChevronRight size={16} className="text-gray-500" />
                                    }
                                    <SeverityBadge severity={group.severity} size="sm" />
                                    <span className="font-semibold text-white text-sm">{name}</span>
                                    {group.cwe && <span className="text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded">{group.cwe}</span>}
                                </div>
                                <div className="flex items-center space-x-4 text-sm text-gray-400">
                                    <span className="hidden sm:block">{group.owasp}</span>
                                    <span className="bg-gray-800 text-gray-300 px-2.5 py-0.5 rounded-full font-semibold text-xs">{group.items.length} host{group.items.length !== 1 ? 's' : ''}</span>
                                </div>
                            </button>

                            {expandedGroups[name] && (
                                <div className="border-t border-gray-800">
                                    {group.items.map((f, idx) => (
                                        <div key={f.id || idx} className="flex items-center justify-between px-8 py-3 border-b border-gray-800/50 hover:bg-gray-800/30">
                                            <div className="flex-1">
                                                <code className="text-xs text-gray-400 bg-gray-800 px-2 py-0.5 rounded">{f.url || f.scan_target}</code>
                                                {f.cvss_score && (
                                                    <span className="ml-3 text-xs font-semibold" style={{ color: SEVERITY_COLORS[f.severity] }}>
                                                        CVSS {f.cvss_score}
                                                    </span>
                                                )}
                                                <p className="text-xs text-gray-500 mt-1 line-clamp-1">{f.description}</p>
                                            </div>
                                            <Link to={`/results/${f.scan_id}`} className="ml-4 text-xs text-purple-400 hover:text-purple-300 flex items-center space-x-1">
                                                <span>View</span><ExternalLink size={11} />
                                            </Link>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            ) : (
                /* Flat View */
                <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
                    <table className="w-full text-sm">
                        <thead>
                            <tr className="border-b border-gray-800 text-left text-gray-500">
                                <th className="px-5 py-3 font-medium">Severity</th>
                                <th className="px-3 py-3 font-medium">Vulnerability</th>
                                <th className="px-3 py-3 font-medium hidden md:table-cell">OWASP</th>
                                <th className="px-3 py-3 font-medium hidden lg:table-cell">CVSS</th>
                                <th className="px-3 py-3 font-medium">Target</th>
                                <th className="px-3 py-3 font-medium"></th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-800">
                            {sorted.map((f, i) => (
                                <tr key={f.id || i} className="hover:bg-gray-800/40 transition-colors">
                                    <td className="px-5 py-3"><SeverityBadge severity={f.severity} size="sm" /></td>
                                    <td className="px-3 py-3 font-medium text-white">{f.name}</td>
                                    <td className="px-3 py-3 text-gray-400 hidden md:table-cell text-xs">{f.owasp}</td>
                                    <td className="px-3 py-3 hidden lg:table-cell">
                                        {f.cvss_score ? (
                                            <span className="font-bold" style={{ color: SEVERITY_COLORS[f.severity] }}>{f.cvss_score}</span>
                                        ) : '—'}
                                    </td>
                                    <td className="px-3 py-3 text-gray-400 text-xs max-w-[200px] truncate">{f.scan_target}</td>
                                    <td className="px-3 py-3">
                                        <Link to={`/results/${f.scan_id}`} className="text-purple-400 hover:text-purple-300 text-xs">View →</Link>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    )
}

export default Vulnerabilities
