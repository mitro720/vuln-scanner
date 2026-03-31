import { useState, useEffect, useRef } from 'react'
import { useParams, Link } from 'react-router-dom'
import SeverityBadge from '../components/common/SeverityBadge'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { Download, FileText, AlertCircle, Shield, ExternalLink, ChevronDown, ChevronUp, Clock, Globe, Cpu, Bot, FileBarChart, Radar, Camera, FlaskConical, Terminal, Copy, Zap } from 'lucide-react'
import RemediationHub from '../components/results/RemediationHub'

const SEVERITY_COLORS = {
    Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#3b82f6', Info: '#8b5cf6'
}
const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 }

/* ── CVSS Gauge ─────────────────────────────────────────────────────────── */
const CvssGauge = ({ score }) => {
    const color = score >= 9 ? '#ef4444' : score >= 7 ? '#f97316' : score >= 4 ? '#eab308' : '#22c55e'
    const pct = Math.min(score / 10, 1) * 100
    return (
        <div className="flex items-center space-x-4 p-4 bg-gray-800 rounded-xl border border-gray-700">
            <div className="relative w-20 h-20 flex-shrink-0">
                <svg viewBox="0 0 80 80" className="w-full h-full -rotate-90">
                    <circle cx="40" cy="40" r="32" fill="none" stroke="#1f2937" strokeWidth="8" />
                    <circle cx="40" cy="40" r="32" fill="none" stroke={color} strokeWidth="8"
                        strokeDasharray={`${(pct / 100) * 201} 201`} strokeLinecap="round"
                        style={{ transition: 'stroke-dasharray 0.8s ease' }} />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-lg font-bold" style={{ color }}>{score}</span>
                </div>
            </div>
            <div>
                <p className="text-xs text-gray-500 mb-0.5">CVSS 3.1 Score</p>
                <p className="text-xl font-bold" style={{ color }}>
                    {score >= 9 ? 'Critical' : score >= 7 ? 'High' : score >= 4 ? 'Medium' : 'Low'}
                </p>
            </div>
        </div>
    )
}

/* ── EPSS Gauge ─────────────────────────────────────────────────────────── */
const EpssGauge = ({ score, percentile }) => {
    // Score is 0-1, convert to percentage
    const pct = (parseFloat(score) * 100).toFixed(2);
    const pctl = (parseFloat(percentile) * 100).toFixed(1);
    const color = pct >= 50 ? '#ef4444' : pct >= 10 ? '#f97316' : pct >= 1 ? '#eab308' : '#22c55e';

    return (
        <div className="flex items-center space-x-4 p-4 bg-gray-900 rounded-xl border border-gray-700">
            <div className="relative w-20 h-20 flex-shrink-0">
                <svg viewBox="0 0 80 80" className="w-full h-full -rotate-90">
                    <circle cx="40" cy="40" r="32" fill="none" stroke="#1f2937" strokeWidth="8" />
                    <circle cx="40" cy="40" r="32" fill="none" stroke={color} strokeWidth="8"
                        strokeDasharray={`${(parseFloat(score)) * 201} 201`} strokeLinecap="round"
                        style={{ transition: 'stroke-dasharray 0.8s ease' }} />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-sm font-bold" style={{ color }}>{pct}%</span>
                </div>
            </div>
            <div>
                <p className="text-xs text-gray-400 mb-0.5 font-semibold">EPSS Probability</p>
                <p className="text-sm font-semibold" style={{ color }}>
                    {pct >= 50 ? 'Critical' : pct >= 10 ? 'High' : pct >= 1 ? 'Medium' : 'Low'} Severity
                </p>
                {percentile && (
                    <p className="text-[10px] text-gray-500 mt-1">
                        {pctl}th Percentile
                    </p>
                )}
            </div>
        </div>
    )
}

/* ── CVE Panel ──────────────────────────────────────────────────────────── */
const CvePanel = ({ scanId, findingName }) => {
    const [cves, setCves] = useState([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const load = async () => {
            setLoading(true)
            try {
                const r = await fetch(`http://localhost:5000/api/scans/${scanId}/cves`)
                if (r.ok) {
                    const d = await r.json()
                    const all = d.data || d || []
                    // Filter CVEs relevant to this finding by service name match
                    const relevant = all.filter(c =>
                        !findingName ||
                        c.service_name?.toLowerCase().includes(findingName.split(' ')[0]?.toLowerCase()) ||
                        c.description?.toLowerCase().includes(findingName.split(' ')[0]?.toLowerCase())
                    )
                    setCves(relevant.slice(0, 8))
                }
            } catch { setCves([]) } finally { setLoading(false) }
        }
        if (scanId) load()
    }, [scanId, findingName])

    if (loading) return <div className="text-xs text-gray-500 py-2">Loading CVE data…</div>
    if (!cves.length) return (
        <div className="text-xs text-gray-500 py-2 flex items-center space-x-2">
            <Shield size={14} />
            <span>No CVEs linked to this finding</span>
        </div>
    )

    return (
        <div className="space-y-2">
            {cves.map((cve, i) => {
                const score = cve.cvss_score || 0
                const color = score >= 9 ? '#ef4444' : score >= 7 ? '#f97316' : score >= 4 ? '#eab308' : '#22c55e'
                return (
                    <div key={cve.cve_id || i} className="flex items-center justify-between bg-gray-800 rounded-lg px-3 py-2 hover:bg-gray-700 transition-colors">
                        <div className="flex items-center space-x-3">
                            <a href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} target="_blank" rel="noopener noreferrer"
                                className="text-blue-400 hover:text-blue-300 font-mono text-xs font-semibold flex items-center space-x-1">
                                <span>{cve.cve_id}</span><ExternalLink size={10} />
                            </a>
                            <span className="text-xs text-gray-400 line-clamp-1 max-w-[220px]">{cve.description}</span>
                        </div>
                        <div className="flex items-center space-x-2 flex-shrink-0">
                            <span className="text-xs font-bold px-2 py-0.5 rounded" style={{ color, background: color + '22' }}>
                                CVSS {score}
                            </span>
                        </div>
                    </div>
                )
            })}
        </div>
    )
}

/* ── Reconnaissance Panel ────────────────────────────────────────────────── */
const ReconPanel = ({ metadata }) => {
    if (!metadata || Object.keys(metadata).length === 0) return (
        <div className="flex flex-col items-center justify-center py-20 bg-gray-900 rounded-xl border border-gray-800 border-dashed">
            <Globe className="text-gray-700 mb-4" size={48} />
            <p className="text-gray-500 italic">No reconnaissance data available for this scan</p>
        </div>
    )

    const waf = metadata.waf
    const technologies = metadata.technologies
    const ports = metadata.ports
    const discovered_urls = metadata.discovered_urls || metadata.live_urls || metadata.subdomains || []


    const techList = technologies?.technologies || []
    const openPorts = ports?.open_ports || []

    return (
        <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* WAF & Tech */}
                <div className="space-y-6">
                    {/* WAF Status */}
                    <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider flex items-center space-x-2">
                                <Shield size={16} className="text-blue-400" />
                                <span>WAF Detection</span>
                            </h3>
                            {waf?.waf_detected ? (
                                <span className="bg-red-500/20 text-red-400 text-[10px] font-bold px-2 py-0.5 rounded-full border border-red-500/30">PROTECTED</span>
                            ) : (
                                <span className="bg-green-500/20 text-green-400 text-[10px] font-bold px-2 py-0.5 rounded-full border border-green-500/30">UNPROTECTED</span>
                            )}
                        </div>
                        {waf?.waf_detected ? (
                            <div className="space-y-3">
                                <div className="flex items-center space-x-2">
                                    <div className="w-2 h-2 rounded-full animate-pulse bg-red-500" />
                                    <p className="text-white font-medium">Detected: {waf.wafs?.join(', ') || 'Generic WAF'}</p>
                                </div>
                                <p className="text-xs text-gray-500">Confidence: <span className="text-gray-300">{waf.confidence || 'Medium'}</span></p>
                            </div>
                        ) : (
                            <p className="text-gray-500 text-sm">No WAF signatures detected or block behavior observed.</p>
                        )}
                    </div>

                    {/* Technologies */}
                    <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                        <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-4 flex items-center space-x-2">
                            <Cpu size={16} className="text-purple-400" />
                            <span>Technology Stack</span>
                        </h3>
                        <div className="space-y-4">
                            <div>
                                <p className="text-xs text-gray-500 mb-1.5 font-medium">Server Engine</p>
                                <code className="bg-gray-950 px-3 py-1.5 rounded-lg text-xs text-purple-300 border border-gray-800 inline-block font-mono">
                                    {technologies?.server || 'Unknown'}
                                </code>
                            </div>
                            <div>
                                <p className="text-xs text-gray-500 mb-2 font-medium">Detected Frameworks / Libraries</p>
                                <div className="flex flex-wrap gap-2">
                                    {techList.length > 0 ? techList.map(t => (
                                        <span key={t} className="bg-gray-800 text-gray-300 px-3 py-1 rounded-full text-xs font-semibold border border-gray-700">
                                            {t}
                                        </span>
                                    )) : <span className="text-gray-500 italic text-sm">None detected</span>}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Ports */}
                <div className="bg-gray-900 rounded-xl border border-gray-800 p-6 flex flex-col">
                    <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-4 flex items-center space-x-2">
                        <Globe size={16} className="text-green-400" />
                        <span>Infrastructure ({ports?.total_open || 0} Open)</span>
                    </h3>
                    {openPorts.length > 0 ? (
                        <div className="flex-1 overflow-x-auto">
                            <table className="w-full text-left text-xs">
                                <thead className="text-gray-500 border-b border-gray-800">
                                    <tr>
                                        <th className="pb-2 font-medium">Port</th>
                                        <th className="pb-2 font-medium">Service</th>
                                        <th className="pb-2 font-medium">Product / Version</th>
                                    </tr>
                                </thead>
                                <tbody className="text-gray-300 divide-y divide-gray-800/40">
                                    {openPorts.map((p, i) => (
                                        <tr key={i} className="hover:bg-white/5 transition-colors">
                                            <td className="py-2.5 font-mono text-green-400">{p.port}</td>
                                            <td className="py-2.5">
                                                <span className="bg-gray-800 px-1.5 py-0.5 rounded text-[10px] uppercase font-bold text-gray-400">
                                                    {p.service}
                                                </span>
                                            </td>
                                            <td className="py-2.5 truncate max-w-[150px]">
                                                {p.product ? `${p.product} ${p.version || ''}` : <span className="text-gray-600">N/A</span>}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <div className="flex-1 flex items-center justify-center text-gray-500 text-sm">
                            No open ports discovered in common range.
                        </div>
                    )}
                </div>
            </div>

            {/* Discovered URLs / Subdomains */}
            <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <div className="flex items-center justify-between mb-4">
                    <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider flex items-center space-x-2">
                        <ExternalLink size={16} className="text-pink-400" />
                        <span>Attack Surface Mapping</span>
                    </h3>
                    <span className="text-xs text-gray-500 font-mono">{discovered_urls?.length || 0} unique endpoints</span>
                </div>
                {discovered_urls?.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[300px] overflow-y-auto pr-2 custom-scrollbar">
                        {discovered_urls.map((url, i) => (
                            <div key={i} className="bg-gray-950 p-2.5 rounded-lg border border-gray-800 flex items-center space-x-2 group hover:border-pink-500/30 transition-all">
                                <div className="w-1.5 h-1.5 rounded-full bg-pink-500/50 group-hover:bg-pink-500" />
                                <span className="text-xs text-gray-400 truncate font-mono">{url}</span>
                            </div>
                        ))}
                    </div>
                ) : (
                    <p className="text-gray-500 text-sm">No subdomains or additional endpoints were discovered.</p>
                )}
            </div>
        </div>
    )
}

/* ── Main Component ─────────────────────────────────────────────────────── */
const Results = () => {
    const { id } = useParams()
    const [findings, setFindings] = useState([])
    const [scanDetails, setScanDetails] = useState(null)
    const [selectedFinding, setSelectedFinding] = useState(null)
    const [loading, setLoading] = useState(true)
    const [activeTab, setActiveTab] = useState('details')
    const [filterSev, setFilterSev] = useState('All')
    const [showCves, setShowCves] = useState(true)
    const [isRemediationOpen, setIsRemediationOpen] = useState(false)
    const [remediationFinding, setRemediationFinding] = useState(null)
    const reportRef = useRef(null)

    useEffect(() => {
        const fetchResults = async () => {
            try {
                const token = JSON.parse(localStorage.getItem('user') || '{}')?.token
                const headers = { 'Authorization': `Bearer ${token}` }

                const scanRes = await fetch(`http://localhost:5000/api/scans/${id}`, { headers })
                const scanData = await scanRes.json()
                setScanDetails(scanData?.data || scanData)

                const findingsRes = await fetch(`http://localhost:5000/api/scans/${id}/findings`, { headers })
                const findingsData = await findingsRes.json()
                const normalized = (findingsData?.data || findingsData || []).map(f => {
                    let evidence = f.evidence || 'No evidence available';
                    let poc_screenshot = null;
                    let alert_captured = null;

                    // Handle JSON evidence from the new PoC engine
                    if (typeof evidence === 'string' && evidence.startsWith('{')) {
                        try {
                            const parsed = JSON.parse(evidence);
                            evidence = parsed.raw || evidence;
                            poc_screenshot = parsed.poc_screenshot;
                            alert_captured = parsed.alert_captured;
                        } catch (e) { /* fallback */ }
                    } else if (typeof evidence === 'object' && evidence !== null) {
                        poc_screenshot = evidence.poc_screenshot;
                        alert_captured = evidence.alert_captured;
                        evidence = evidence.raw || JSON.stringify(evidence, null, 2);
                    }

                    return {
                        ...f,
                        remediation: Array.isArray(f.remediation) ? f.remediation
                            : typeof f.remediation === 'string' ? f.remediation.split('\n').filter(Boolean)
                                : ['No remediation steps available'],
                        evidence,
                        poc_screenshot,
                        alert_captured,
                        poc: f.poc || 'No proof of concept available',
                    }
                })
                const sorted = [...normalized].sort((a, b) =>
                    (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
                )
                setFindings(sorted)
                if (sorted.length > 0) setSelectedFinding(sorted[0])
            } catch (e) {
                console.error('Error fetching results:', e)
            } finally {
                setLoading(false)
            }
        }
        fetchResults()
    }, [id])

    /* ── PDF Export ─────────────────────────────────────────────────────── */
    const exportPDF = async () => {
        const { default: jsPDF } = await import('jspdf')
        const { default: html2canvas } = await import('html2canvas')
        const element = reportRef.current
        if (!element) return

        const canvas = await html2canvas(element, { backgroundColor: '#111827', scale: 1.5, useCORS: true })
        const imgData = canvas.toDataURL('image/png')
        const pdf = new jsPDF({ orientation: 'portrait', unit: 'px', format: 'a4' })
        const pageW = pdf.internal.pageSize.getWidth()
        const pageH = pdf.internal.pageSize.getHeight()
        const imgW = pageW
        const imgH = (canvas.height * imgW) / canvas.width
        let offset = 0
        while (offset < imgH) {
            if (offset > 0) pdf.addPage()
            pdf.addImage(imgData, 'PNG', 0, -offset, imgW, imgH)
            offset += pageH
        }
        pdf.save(`SecureScan-Report-${id}.pdf`)
    }

    /* ── CSV Export ──────────────────────────── */
    const exportCSV = () => {
        const headers = ['Name', 'Severity', 'CVSS', 'OWASP', 'CWE', 'URL', 'Confidence', 'Description']
        const rows = findings.map(f => [
            `"${f.name || ''}"`, f.severity || '', f.cvss_score || '',
            `"${f.owasp || ''}"`, f.cwe || '', `"${f.url || ''}"`,
            f.confidence || '', `"${(f.description || '').replace(/"/g, "'")}"`,
        ])
        const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
        const blob = new Blob([csv], { type: 'text/csv' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url; a.download = `SecureScan-${id}.csv`; a.click()
        URL.revokeObjectURL(url)
    }

    /* ── Severity stats ─────────────────────── */
    const sevStats = ['Critical', 'High', 'Medium', 'Low', 'Info'].map(s => ({
        name: s, value: findings.filter(f => f.severity === s).length, fill: SEVERITY_COLORS[s],
    }))

    const filtered = filterSev === 'All' ? findings : findings.filter(f => f.severity === filterSev)

    if (loading) return (
        <div className="flex items-center justify-center min-h-[60vh]">
            <div className="text-center">
                <div className="w-12 h-12 border-4 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
                <p className="text-gray-400">Loading scan results…</p>
            </div>
        </div>
    )

    if (!scanDetails) return (
        <div className="max-w-7xl mx-auto px-4 py-16 text-center">
            <AlertCircle size={48} className="mx-auto mb-4 text-gray-600" />
            <p className="text-gray-400">Scan not found.</p>
            <Link to="/history" className="text-purple-400 hover:text-purple-300 mt-4 inline-block">← Back to History</Link>
        </div>
    )

    return (
        <div className="max-w-7xl mx-auto px-4 pb-10">
            {/* Header */}
            <div className="flex items-start justify-between mb-6">
                <div>
                    <h1 className="text-3xl font-bold text-gradient">Scan Report</h1>
                    <div className="flex items-center space-x-4 mt-2 text-sm text-gray-400">
                        <span className="flex items-center space-x-1"><Globe size={13} /><span>{scanDetails.target_url}</span></span>
                        <span className="flex items-center space-x-1"><Clock size={13} /><span>{new Date(scanDetails.created_at).toLocaleString()}</span></span>
                        <span className="flex items-center space-x-1"><Cpu size={13} /><span>{scanDetails.scan_type || 'full'} scan</span></span>
                    </div>
                </div>
                <div className="flex space-x-2">
                    <Link to={`/visual-surface/${id}`}
                        className="flex items-center space-x-2 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700 text-sm transition-colors text-blue-400">
                        <Camera size={15} /><span>Visual Surface</span>
                    </Link>
                    <Link to={`/attack-surface?scanId=${id}`}
                        className="flex items-center space-x-2 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700 text-sm transition-colors text-purple-400">
                        <Radar size={15} /><span>Surface Map</span>
                    </Link>
                    <Link to={`/report/${id}`}
                        className="flex items-center space-x-2 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700 text-sm transition-colors">
                        <FileBarChart size={15} /><span>Full Report</span>
                    </Link>
                    <button onClick={exportCSV} className="flex items-center space-x-2 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700 text-sm transition-colors">
                        <FileText size={15} /><span>CSV</span>
                    </button>
                    <button onClick={exportPDF} className="flex items-center space-x-2 px-4 py-2 gradient-bg text-white rounded-lg hover:shadow-lg hover:shadow-purple-500/20 text-sm transition-all">
                        <Download size={15} /><span>Export PDF</span>
                    </button>
                </div>
            </div>

            {/* Summary Strip */}
            <div ref={reportRef}>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-6">
                    {sevStats.map(s => (
                        <button key={s.name}
                            onClick={() => setFilterSev(filterSev === s.name ? 'All' : s.name)}
                            className={`rounded-xl p-4 border transition-all text-center cursor-pointer ${filterSev === s.name ? 'border-opacity-100 scale-105 shadow-lg' : 'border-gray-800 hover:border-gray-700'}`}
                            style={{ background: s.fill + '18', borderColor: filterSev === s.name ? s.fill : undefined }}>
                            <div className="text-3xl font-bold" style={{ color: s.fill }}>{s.value}</div>
                            <div className="text-xs text-gray-400 mt-1">{s.name}</div>
                        </button>
                    ))}
                </div>

                {findings.length === 0 ? (
                    <div className="bg-gray-900 rounded-xl border border-gray-800 p-16 text-center">
                        <Shield size={56} className="mx-auto mb-4 text-green-500/50" />
                        <h2 className="text-xl font-bold text-white mb-2">No Vulnerabilities Found</h2>
                        <p className="text-gray-400">This scan completed with no security issues detected.</p>
                    </div>
                ) : (
                    <div className="grid grid-cols-3 gap-5">
                        {/* Findings List */}
                        <div className="col-span-1 space-y-2 max-h-[75vh] overflow-y-auto pr-1">
                            <div className="flex items-center justify-between mb-2">
                                <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
                                    Findings ({filtered.length})
                                </h3>
                                <select value={filterSev} onChange={e => setFilterSev(e.target.value)}
                                    className="text-xs bg-gray-800 border border-gray-700 text-gray-300 rounded-lg px-2 py-1 outline-none">
                                    {['All', 'Critical', 'High', 'Medium', 'Low', 'Info'].map(s => (
                                        <option key={s}>{s}</option>
                                    ))}
                                </select>
                            </div>
                            {filtered.map(f => (
                                <div key={f.id}
                                    onClick={() => { setSelectedFinding(f); setActiveTab('details') }}
                                    className={`p-4 bg-gray-900 rounded-xl cursor-pointer transition-all border ${selectedFinding?.id === f.id ? 'border-purple-500 shadow-lg shadow-purple-500/10' : 'border-gray-800 hover:border-gray-700'}`}>
                                    <div className="flex items-center justify-between mb-2">
                                        <SeverityBadge severity={f.severity} size="sm" />
                                        {f.cvss_score && (
                                            <span className="text-xs font-bold" style={{ color: SEVERITY_COLORS[f.severity] }}>
                                                {f.cvss_score}
                                            </span>
                                        )}
                                    </div>
                                    <h3 className="font-semibold text-white text-sm leading-snug">{f.name}</h3>
                                    <p className="text-xs text-gray-500 mt-1">{f.owasp}</p>
                                    {f.confidence && (
                                        <div className="mt-2 w-full bg-gray-800 rounded-full h-1">
                                            <div className="h-1 rounded-full bg-purple-500" style={{ width: `${f.confidence}%` }} />
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>

                        {/* Finding Detail Panel */}
                        <div className="col-span-2">
                            {selectedFinding ? (
                                <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
                                    {/* Finding Header */}
                                    <div className="px-6 py-5 border-b border-gray-800" style={{ background: SEVERITY_COLORS[selectedFinding.severity] + '12' }}>
                                        <div className="flex items-start justify-between">
                                            <h2 className="text-xl font-bold text-white pr-4">{selectedFinding.name}</h2>
                                            <div className="flex items-center space-x-2">
                                                <button
                                                    onClick={() => { setRemediationFinding(selectedFinding); setIsRemediationOpen(true); }}
                                                    className="flex items-center space-x-1.5 px-3 py-1.5 bg-purple-600/20 border border-purple-500/40 text-purple-300 hover:bg-purple-600/30 rounded-lg text-xs font-semibold transition-all">
                                                    <Bot size={13} /><span>Ask AI</span>
                                                </button>
                                                <SeverityBadge severity={selectedFinding.severity} size="lg" />
                                            </div>
                                        </div>
                                        <div className="flex items-center space-x-4 mt-3 text-xs text-gray-400">
                                            {selectedFinding.owasp && <span className="bg-gray-800 px-2 py-1 rounded">{selectedFinding.owasp}</span>}
                                            {selectedFinding.cwe && (
                                                <a href={`https://cwe.mitre.org/data/definitions/${selectedFinding.cwe?.replace('CWE-', '')}.html`}
                                                    target="_blank" rel="noopener noreferrer"
                                                    className="text-purple-400 hover:text-purple-300 flex items-center space-x-1">
                                                    <span>{selectedFinding.cwe}</span><ExternalLink size={10} />
                                                </a>
                                            )}
                                            {selectedFinding.confidence && <span>{selectedFinding.confidence}% confidence</span>}
                                        </div>
                                    </div>

                                    {/* Tabs */}
                                    <div className="flex border-b border-gray-800">
                                        {['details', 'recon', 'evidence', 'payload', 'cve', 'remediation'].map(tab => (
                                            <button key={tab}
                                                onClick={() => setActiveTab(tab)}
                                                className={`px-5 py-3 text-sm font-medium capitalize transition-colors ${activeTab === tab ? 'text-purple-400 border-b-2 border-purple-500' : 'text-gray-500 hover:text-gray-300'}`}>
                                                {tab === 'payload' ? 'Payload Lab' : tab === 'recon' ? 'Reconnaissance' : tab === 'cve' ? 'CVE / CVSS' : tab}
                                            </button>
                                        ))}
                                    </div>

                                    <div className="p-6 space-y-5 max-h-[60vh] overflow-y-auto">
                                        {/* Recon Tab */}
                                        {activeTab === 'recon' && (
                                            <ReconPanel metadata={scanDetails?.metadata} />
                                        )}
                                        {/* Details Tab */}
                                        {activeTab === 'details' && (
                                            <>
                                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                                                    {selectedFinding.cvss_score && <CvssGauge score={selectedFinding.cvss_score} />}
                                                    {selectedFinding.epss_score && <EpssGauge score={selectedFinding.epss_score} percentile={selectedFinding.epss_percentile} />}
                                                </div>
                                                <div>
                                                    <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Description</h4>
                                                    <p className="text-gray-300 text-sm leading-relaxed">{selectedFinding.description || 'No description available.'}</p>
                                                </div>
                                                <div>
                                                    <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Affected Location</h4>
                                                    <code className="block bg-gray-800 text-green-400 px-4 py-3 rounded-lg text-sm font-mono break-all">{selectedFinding.url || scanDetails.target_url}</code>
                                                </div>
                                                {selectedFinding.technique && (
                                                    <div>
                                                        <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Detection Technique</h4>
                                                        <p className="text-gray-300 text-sm">{selectedFinding.technique}</p>
                                                    </div>
                                                )}
                                                {selectedFinding.cvss_vector && (
                                                    <div>
                                                        <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">CVSS Vector</h4>
                                                        <code className="text-xs bg-gray-800 px-3 py-2 rounded-lg font-mono text-gray-300 block">{selectedFinding.cvss_vector}</code>
                                                    </div>
                                                )}
                                            </>
                                        )}

                                        {/* Evidence Tab */}
                                        {activeTab === 'evidence' && (
                                            <>
                                                <div>
                                                    <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Technical Evidence</h4>
                                                    <pre className="bg-gray-950 text-green-400 p-4 rounded-lg text-xs overflow-x-auto font-mono leading-relaxed border border-gray-800">
                                                        {selectedFinding.evidence}
                                                    </pre>
                                                </div>
                                                
                                                {selectedFinding.poc_screenshot && (
                                                    <div className="space-y-3">
                                                        <div className="flex items-center justify-between">
                                                            <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Automated PoC Screenshot</h4>
                                                            <span className="flex items-center space-x-1 text-[10px] font-bold text-green-400 bg-green-500/10 px-2 py-0.5 rounded border border-green-500/20 uppercase tracking-tighter">
                                                                <Camera size={10} />
                                                                <span>Live Capture</span>
                                                            </span>
                                                        </div>
                                                        <div className="group relative rounded-xl border border-gray-800 overflow-hidden bg-gray-950 shadow-xl shadow-black/50">
                                                            <img 
                                                                src={`http://localhost:5000/screenshots/${selectedFinding.poc_screenshot}`} 
                                                                alt="Proof of Concept" 
                                                                className="w-full h-auto cursor-zoom-in transition-transform group-hover:scale-[1.02]"
                                                                onClick={() => window.open(`http://localhost:5000/screenshots/${selectedFinding.poc_screenshot}`, '_blank')}
                                                            />
                                                            {selectedFinding.alert_captured && (
                                                                <div className="absolute top-4 left-4 right-4 animate-in slide-in-from-top-4 duration-700">
                                                                    <div className="bg-white/95 backdrop-blur shadow-2xl rounded-lg p-3 border border-gray-200">
                                                                        <div className="flex items-center space-x-2 text-gray-800 font-bold text-[10px] uppercase mb-1">
                                                                            <AlertCircle size={12} className="text-blue-600" />
                                                                            <span>Browser Alert Intercepted</span>
                                                                        </div>
                                                                        <p className="text-xs text-gray-700 font-mono italic break-all">"{selectedFinding.alert_captured}"</p>
                                                                    </div>
                                                                </div>
                                                            )}
                                                            <div className="absolute bottom-0 inset-x-0 bg-gradient-to-t from-black/80 to-transparent p-4 opacity-0 group-hover:opacity-100 transition-opacity">
                                                                <p className="text-[10px] text-gray-400 font-medium">Click to expand visual evidence</p>
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}
                                                <div>
                                                    <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Proof of Concept</h4>
                                                    <pre className="bg-gray-950 text-blue-400 p-4 rounded-lg text-xs overflow-x-auto font-mono leading-relaxed border border-gray-800">
                                                        {selectedFinding.poc}
                                                    </pre>
                                                </div>
                                                <div className="flex space-x-3">
                                                    <button
                                                        onClick={() => setSelectedFinding(prev => ({ ...prev, _fp: !prev._fp }))}
                                                        className={`flex-1 py-2.5 border-2 font-semibold rounded-lg text-sm transition-all ${selectedFinding._fp ? 'border-yellow-500 text-yellow-400 bg-yellow-500/10' : 'border-gray-700 text-gray-400 hover:border-yellow-600'}`}>
                                                        {selectedFinding._fp ? '✓ Marked as False Positive' : 'Mark as False Positive'}
                                                    </button>
                                                </div>
                                            </>
                                        )}

                                        {/* Payload Lab Tab */}
                                        {activeTab === 'payload' && (
                                            <div className="space-y-6">
                                                <div className="flex items-center justify-between">
                                                    <div>
                                                        <h4 className="text-sm font-bold text-white flex items-center space-x-2">
                                                            <FlaskConical size={16} className="text-pink-500" />
                                                            <span>Vulnerability Payload Lab</span>
                                                        </h4>
                                                        <p className="text-xs text-gray-500 mt-1">Ready-to-use Proof of Concept payloads for verification.</p>
                                                    </div>
                                                </div>

                                                <div className="grid grid-cols-1 gap-4">
                                                    {(selectedFinding.pocs || []).length > 0 ? (
                                                        selectedFinding.pocs.map((poc, idx) => (
                                                            <div key={idx} className="bg-gray-950 border border-gray-800 rounded-xl overflow-hidden hover:border-pink-500/30 transition-all">
                                                                <div className="px-4 py-2.5 bg-gray-900 border-b border-gray-800 flex items-center justify-between">
                                                                    <span className="text-xs font-bold text-pink-400 uppercase tracking-tighter">{poc.name}</span>
                                                                    <div className="flex items-center space-x-2">
                                                                        <button
                                                                            onClick={() => { navigator.clipboard.writeText(poc.payload); alert('Payload copied!') }}
                                                                            className="p-1 px-2 bg-gray-800 rounded text-[10px] text-gray-400 hover:text-white flex items-center space-x-1">
                                                                            <Copy size={10} /><span>Copy</span>
                                                                        </button>
                                                                    </div>
                                                                </div>
                                                                <div className="p-4">
                                                                    <div className="flex items-start space-x-3 mb-3">
                                                                        <Terminal size={14} className="text-gray-600 mt-1" />
                                                                        <code className="text-xs font-mono text-blue-300 break-all">{poc.payload}</code>
                                                                    </div>
                                                                    {poc.full_url && (
                                                                        <div className="pt-3 border-t border-gray-800/50">
                                                                            <p className="text-[10px] text-gray-500 mb-1.5 font-semibold uppercase">Exploit URL</p>
                                                                            <div className="flex items-center justify-between space-x-2">
                                                                                <code className="text-[10px] font-mono text-gray-400 truncate flex-1">{poc.full_url}</code>
                                                                                <a href={poc.full_url} target="_blank" rel="noopener noreferrer" className="p-1 px-2 bg-pink-600/20 text-pink-400 rounded text-[10px] hover:bg-pink-600/30 font-bold transition-all flex items-center space-x-1">
                                                                                    <ExternalLink size={10} /><span>Verify Live</span>
                                                                                </a>
                                                                            </div>
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            </div>
                                                        ))
                                                    ) : (
                                                        <div className="py-10 text-center bg-gray-950 rounded-xl border border-gray-800 border-dashed">
                                                            <p className="text-gray-500 italic text-sm">No automated PoCs available for this finding type.</p>
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        )}

                                        {/* CVE Tab */}
                                        {activeTab === 'cve' && (
                                            <div className="space-y-4">
                                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                    {selectedFinding.cvss_score && <CvssGauge score={selectedFinding.cvss_score} />}
                                                    {selectedFinding.epss_score && <EpssGauge score={selectedFinding.epss_score} percentile={selectedFinding.epss_percentile} />}
                                                </div>
                                                <div>
                                                    <div className="flex items-center justify-between mb-3">
                                                        <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Related CVEs</h4>
                                                    </div>
                                                    <CvePanel scanId={id} findingName={selectedFinding.name} />
                                                </div>
                                                <div className="text-xs text-gray-600 flex items-center space-x-1 pt-2">
                                                    <span>CVE data provided by NIST NVD</span>
                                                    <ExternalLink size={10} />
                                                </div>
                                            </div>
                                        )}

                                        {/* Remediation Tab */}
                                        {activeTab === 'remediation' && (
                                            <>
                                                <div>
                                                    <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Remediation Steps</h4>
                                                    <ol className="space-y-3">
                                                        {selectedFinding.remediation.map((step, i) => (
                                                            <li key={i} className="flex items-start space-x-3">
                                                                <span className="flex-shrink-0 w-6 h-6 gradient-bg rounded-full text-white text-xs flex items-center justify-center font-bold mt-0.5">{i + 1}</span>
                                                                <p className="text-gray-300 text-sm leading-relaxed">{step}</p>
                                                            </li>
                                                        ))}
                                                    </ol>
                                                </div>

                                                <div className="bg-purple-900/10 border border-purple-500/20 rounded-xl p-5 mt-6">
                                                    <div className="flex items-start space-x-4">
                                                        <div className="p-3 bg-purple-600/20 rounded-xl text-purple-400">
                                                            <Bot size={24} />
                                                        </div>
                                                        <div className="flex-1">
                                                            <h4 className="text-sm font-bold text-white mb-1">AI-Powered Remediation Advice</h4>
                                                            <p className="text-xs text-gray-400 leading-relaxed mb-4">Get a detailed, stack-specific fix for this vulnerability drafted by our AI Security Oracle.</p>
                                                            <button 
                                                                onClick={() => { setRemediationFinding(selectedFinding); setIsRemediationOpen(true); }}
                                                                className="flex items-center space-x-2 px-4 py-2 gradient-bg text-white rounded-lg text-xs font-bold transition-all shadow-lg hover:shadow-purple-500/30 active:scale-95"
                                                            >
                                                                <Zap size={14} />
                                                                <span>Generate AI Fix</span>
                                                            </button>
                                                        </div>
                                                    </div>
                                                </div>
                                                {selectedFinding.references?.length > 0 && (
                                                    <div>
                                                        <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">References</h4>
                                                        <ul className="space-y-1">
                                                            {selectedFinding.references.slice(0, 5).map((ref, i) => (
                                                                <li key={i}>
                                                                    <a href={ref} target="_blank" rel="noopener noreferrer"
                                                                        className="text-blue-400 hover:text-blue-300 text-xs flex items-center space-x-1 truncate">
                                                                        <ExternalLink size={10} className="flex-shrink-0" /><span>{ref}</span>
                                                                    </a>
                                                                </li>
                                                            ))}
                                                        </ul>
                                                    </div>
                                                )}
                                            </>
                                        )}
                                    </div>
                                </div>
                            ) : (
                                <div className="bg-gray-900 rounded-xl border border-gray-800 flex items-center justify-center min-h-[500px]">
                                    <div className="text-center text-gray-500">
                                        <AlertCircle size={48} className="mx-auto mb-3" />
                                        <p>Select a finding to view details</p>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>

            {/* AI Remediation Hub */}
            <RemediationHub 
                isOpen={isRemediationOpen} 
                onClose={() => setIsRemediationOpen(false)} 
                finding={remediationFinding} 
            />
        </div>
    )
}

export default Results
