import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Globe, Shield, Clock, AlertTriangle, TrendingUp, ChevronRight } from 'lucide-react'

const SEVERITY_COLORS = {
    Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#3b82f6', Info: '#8b5cf6'
}

const getRiskScore = (scan) => {
    const c = (scan.critical_count || 0) * 10
    const h = (scan.high_count || 0) * 7
    const m = (scan.medium_count || 0) * 4
    const l = (scan.low_count || 0) * 1
    return Math.min((c + h + m + l) / 20, 10).toFixed(1)
}

const getRiskColor = (score) => {
    if (score >= 8) return '#ef4444'
    if (score >= 6) return '#f97316'
    if (score >= 4) return '#eab308'
    return '#22c55e'
}

const RiskBar = ({ score }) => {
    const color = getRiskColor(Number(score))
    return (
        <div className="flex items-center space-x-2">
            <div className="flex-1 bg-gray-800 rounded-full h-1.5">
                <div className="h-1.5 rounded-full transition-all duration-700"
                    style={{ width: `${(score / 10) * 100}%`, backgroundColor: color }} />
            </div>
            <span className="text-xs font-bold w-8" style={{ color }}>{score}</span>
        </div>
    )
}

const Assets = () => {
    const [scans, setScans] = useState([])
    const [assets, setAssets] = useState([])
    const [loading, setLoading] = useState(true)
    const [sortBy, setSortBy] = useState('risk')
    const [search, setSearch] = useState('')

    useEffect(() => {
        const load = async () => {
            try {
                const r = await fetch('http://localhost:5000/api/scans')
                if (!r.ok) return
                const data = await r.json()
                const arr = data.data || []
                setScans(arr)

                // Deduplicate by target host
                const hostMap = {}
                arr.forEach(scan => {
                    let host = scan.target_url || 'Unknown'
                    try { host = new URL(scan.target_url).hostname } catch { /* keep raw */ }

                    if (!hostMap[host]) {
                        hostMap[host] = {
                            host,
                            scans: [],
                            totalFindings: 0,
                            criticalCount: 0,
                            highCount: 0,
                            lastSeen: null,
                            firstSeen: null,
                        }
                    }
                    const entry = hostMap[host]
                    entry.scans.push(scan)
                    entry.totalFindings += scan.findings_count || 0
                    entry.criticalCount += scan.critical_count || 0
                    entry.highCount += scan.high_count || 0
                    const dt = new Date(scan.created_at)
                    if (!entry.lastSeen || dt > entry.lastSeen) entry.lastSeen = dt
                    if (!entry.firstSeen || dt < entry.firstSeen) entry.firstSeen = dt
                })

                const list = Object.values(hostMap).map(a => ({
                    ...a,
                    riskScore: getRiskScore(a.scans[0] || {}),
                }))
                setAssets(list)
            } catch (e) {
                console.error(e)
            } finally {
                setLoading(false)
            }
        }
        load()
    }, [])

    const filtered = assets
        .filter(a => !search || a.host.toLowerCase().includes(search.toLowerCase()))
        .sort((a, b) => {
            if (sortBy === 'risk') return Number(b.riskScore) - Number(a.riskScore)
            if (sortBy === 'findings') return b.totalFindings - a.totalFindings
            if (sortBy === 'scans') return b.scans.length - a.scans.length
            return a.host.localeCompare(b.host)
        })

    return (
        <div className="max-w-7xl mx-auto px-4 pb-10">
            {/* Header */}
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-4xl font-bold text-gradient">Asset Inventory</h1>
                    <p className="text-gray-400 mt-1">{filtered.length} unique host{filtered.length !== 1 ? 's' : ''} tracked</p>
                </div>
                <Link to="/scan/new" className="px-5 py-2.5 gradient-bg text-white font-semibold rounded-lg shadow-lg hover:shadow-purple-500/30 transition-all text-sm">
                    + Scan New Asset
                </Link>
            </div>

            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                {[
                    { label: 'Total Assets', value: assets.length, icon: Globe, color: '#8b5cf6' },
                    { label: 'High Risk', value: assets.filter(a => Number(a.riskScore) >= 6).length, icon: AlertTriangle, color: '#ef4444' },
                    { label: 'Total Findings', value: assets.reduce((s, a) => s + a.totalFindings, 0), icon: Shield, color: '#f97316' },
                    { label: 'Total Scans', value: scans.length, icon: TrendingUp, color: '#22c55e' },
                ].map(({ label, value, icon: Icon, color }) => (
                    <div key={label} className="bg-gray-900 rounded-xl p-5 border border-gray-800">
                        <div className="flex items-center justify-between mb-3">
                            <p className="text-sm text-gray-400">{label}</p>
                            <div className="p-2 rounded-lg" style={{ background: color + '22' }}>
                                <Icon size={16} style={{ color }} />
                            </div>
                        </div>
                        <p className="text-3xl font-bold text-white">{value}</p>
                    </div>
                ))}
            </div>

            {/* Filters */}
            <div className="flex gap-3 mb-5">
                <div className="flex-1 relative">
                    <Globe size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                    <input
                        type="text"
                        placeholder="Search hosts..."
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        className="w-full pl-9 pr-4 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:ring-1 focus:ring-purple-500 outline-none"
                    />
                </div>
                <select value={sortBy} onChange={e => setSortBy(e.target.value)}
                    className="px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-300 outline-none focus:ring-1 focus:ring-purple-500">
                    <option value="risk">Sort: Risk Score</option>
                    <option value="findings">Sort: Findings</option>
                    <option value="scans">Sort: Scan Count</option>
                    <option value="host">Sort: Hostname</option>
                </select>
            </div>

            {/* Assets Table */}
            {loading ? (
                <div className="text-center py-16 text-gray-500">Loading assets…</div>
            ) : filtered.length === 0 ? (
                <div className="bg-gray-900 rounded-xl border border-gray-800 p-16 text-center">
                    <Globe size={48} className="mx-auto mb-4 text-gray-700" />
                    <p className="text-gray-400">No assets discovered yet.</p>
                    <Link to="/scan/new" className="text-purple-400 hover:text-purple-300 text-sm mt-3 inline-block">Start your first scan →</Link>
                </div>
            ) : (
                <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
                    <table className="w-full text-sm">
                        <thead>
                            <tr className="border-b border-gray-800 text-left text-gray-500 text-xs uppercase tracking-wider">
                                <th className="px-5 py-3 font-medium">Host</th>
                                <th className="px-4 py-3 font-medium">Risk Score</th>
                                <th className="px-4 py-3 font-medium hidden md:table-cell">Findings</th>
                                <th className="px-4 py-3 font-medium hidden md:table-cell">Critical / High</th>
                                <th className="px-4 py-3 font-medium hidden lg:table-cell">Scans</th>
                                <th className="px-4 py-3 font-medium hidden lg:table-cell">Last Seen</th>
                                <th className="px-4 py-3 font-medium"></th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-800">
                            {filtered.map((asset, i) => {
                                const rColor = getRiskColor(Number(asset.riskScore))
                                const lastScan = asset.scans[0]
                                return (
                                    <tr key={asset.host} className="hover:bg-gray-800/40 transition-colors">
                                        <td className="px-5 py-4">
                                            <div className="flex items-center space-x-3">
                                                <div className="w-8 h-8 rounded-lg bg-gray-800 flex items-center justify-center flex-shrink-0">
                                                    <Globe size={14} className="text-purple-400" />
                                                </div>
                                                <div>
                                                    <p className="font-semibold text-white">{asset.host}</p>
                                                    <p className="text-xs text-gray-500">{asset.scans[0]?.target_url}</p>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-4 py-4 w-40">
                                            <RiskBar score={asset.riskScore} />
                                        </td>
                                        <td className="px-4 py-4 hidden md:table-cell font-semibold text-white">{asset.totalFindings}</td>
                                        <td className="px-4 py-4 hidden md:table-cell">
                                            <span className="text-red-400 font-bold">{asset.criticalCount}C</span>
                                            <span className="text-gray-600 mx-1">/</span>
                                            <span className="text-orange-400 font-bold">{asset.highCount}H</span>
                                        </td>
                                        <td className="px-4 py-4 hidden lg:table-cell text-gray-400">{asset.scans.length}</td>
                                        <td className="px-4 py-4 hidden lg:table-cell text-gray-500 text-xs">
                                            {asset.lastSeen ? asset.lastSeen.toLocaleDateString() : '—'}
                                        </td>
                                        <td className="px-4 py-4">
                                            {lastScan && (
                                                <Link to={`/results/${lastScan.id}`}
                                                    className="flex items-center space-x-1 text-purple-400 hover:text-purple-300 text-xs font-medium">
                                                    <span>Report</span><ChevronRight size={12} />
                                                </Link>
                                            )}
                                        </td>
                                    </tr>
                                )
                            })}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    )
}

export default Assets
