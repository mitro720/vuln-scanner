import { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import SeverityBadge from '../components/common/SeverityBadge'
import { AlertTriangle, CheckCircle2, Clock, ExternalLink, Zap } from 'lucide-react'

const API = 'http://localhost:5000/api'

/* ── Scan phase definitions ────────────────────────────────────────────── */
const PHASES = [
    { id: 'recon', label: 'Reconnaissance', icon: '🌐', desc: 'DNS, WHOIS, headers, tech fingerprinting', range: [0, 20] },
    { id: 'port', label: 'Port Scanning', icon: '🔌', desc: 'Open ports, service detection, banners', range: [20, 40] },
    { id: 'owasp', label: 'OWASP Top 10', icon: '🛡️', desc: 'XSS, SQLi, CSRF, misconfigs, injections', range: [40, 70] },
    { id: 'cve', label: 'CVE Detection', icon: '🐛', desc: 'NVD cross-reference for detected services', range: [70, 90] },
    { id: 'report', label: 'Generating Report', icon: '📋', desc: 'Aggregating findings and scoring', range: [90, 100] },
]

function getPhaseForProgress(progress) {
    return PHASES.findIndex(p => progress >= p.range[0] && progress < p.range[1])
}

const PhaseBar = ({ progress, isRunning, currentPhase, scanType, selectedPhase, onPhaseSelect }) => {
    const activeIdx = getPhaseForProgress(Math.min(progress, 99))
    const isModular = scanType?.startsWith('modular:')
    const targetPhase = isModular ? scanType.split(':')[1] : null

    return (
        <div className="space-y-6 mb-8">
            {/* Linear progress */}
            <div className="w-full bg-gray-950/50 p-1.5 rounded-full border border-gray-800/50 shadow-inner">
                <div className="h-3 rounded-full transition-all duration-1000 relative overflow-hidden"
                    style={{ width: `${progress}%`, background: 'linear-gradient(90deg, #7c3aed, #a855f7, #3b82f6)' }}>
                    {isRunning && (
                        <div className="absolute inset-0 opacity-40 bg-[length:200%_100%] animate-shimmer"
                            style={{ background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent)' }} />
                    )}
                </div>
            </div>

            {/* Phase steps */}
            <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
                {PHASES.map((phase, i) => {
                    const isDone = progress >= phase.range[1]
                    const isActive = i === activeIdx && isRunning

                    // Logic for "Not Tested" in modular scans
                    const isSkipped = isModular && targetPhase !== phase.id && !isDone && !isActive

                    return (
                        <div key={phase.id}
                            onClick={() => onPhaseSelect(phase.id)}
                            className={`group relative rounded-2xl p-4 border transition-all duration-500 overflow-hidden cursor-pointer ${isDone
                                ? selectedPhase === phase.id ? 'bg-green-500/10 border-green-500' : 'bg-green-500/5 border-green-500/40'
                                : isActive
                                    ? 'bg-purple-500/10 border-purple-500 shadow-[0_0_20px_rgba(168,85,247,0.15)] scale-[1.02]'
                                    : isSkipped
                                        ? 'bg-gray-900/20 border-gray-800/30 opacity-40 grayscale'
                                        : selectedPhase === phase.id ? 'bg-gray-800 border-gray-600' : 'bg-gray-900/40 border-gray-800'
                                }`}>
                            {isActive && <div className="absolute top-0 right-0 p-2"><div className="w-1.5 h-1.5 bg-purple-500 rounded-full animate-ping" /></div>}
                            <div className={`text-3xl mb-2 transition-transform group-hover:scale-110 ${isSkipped ? 'opacity-30' : ''}`}>{phase.icon}</div>

                            <div className={`text-[10px] font-black uppercase tracking-widest mb-1 ${isDone ? 'text-green-500' : isActive ? 'text-purple-400' : isSkipped ? 'text-gray-600' : 'text-gray-500'
                                }`}>
                                {isDone ? '✓ Verified' : isActive ? '● Active' : isSkipped ? '⊘ Skipped' : '○ Standby'}
                            </div>

                            <div className={`text-sm font-bold ${isDone ? 'text-green-200' : isActive ? 'text-white' : 'text-gray-500'}`}>
                                {phase.label}
                            </div>

                            {isActive && (
                                <div className="mt-2 h-0.5 w-full bg-gray-800 rounded-full overflow-hidden">
                                    <div className="h-full bg-purple-500 animate-loading" />
                                </div>
                            )}
                        </div>
                    )
                })}
            </div>

            {/* Current step description */}
            {isRunning && activeIdx >= 0 && (
                <div className="flex items-center justify-center space-x-3 text-purple-300">
                    <Zap size={14} className="animate-bounce" />
                    <span className="text-xs font-mono uppercase tracking-[0.2em] animate-pulse">
                        {currentPhase || PHASES[activeIdx]?.desc}
                    </span>
                </div>
            )}
        </div>
    )
}

const LiveScan = () => {
    const { id } = useParams()
    const navigate = useNavigate()
    const [scan, setScan] = useState(null)
    const [findings, setFindings] = useState([])
    const [logs, setLogs] = useState([])
    const [loading, setLoading] = useState(true)
    const [activity, setActivity] = useState([])
    const [selectedPhase, setSelectedPhase] = useState('recon')
    const [services, setServices] = useState([])
    const [reconData, setReconData] = useState(null)
    const logsEndRef = useRef(null)

    useEffect(() => {
        const fetchScanData = async () => {
            try {
                const [scanRes, findingsRes, servicesRes, reconRes] = await Promise.all([
                    fetch(`${API}/scans/${id}`),
                    fetch(`${API}/scans/${id}/findings`),
                    fetch(`${API}/scans/${id}/services`),
                    fetch(`${API}/crawl/scan/${id}`),
                ])
                const scanData = await scanRes.json()
                const findData = await findingsRes.json()
                const servData = await servicesRes.json()
                const rcData = await reconRes.json()

                const scanObj = scanData.data || scanData
                setScan(scanObj)
                setFindings(findData.data || [])
                setServices(servData.data || [])
                setReconData(rcData.success ? rcData.data : null)

                if (scanObj.current_phase) {
                    setActivity(prev => {
                        const last = prev[0]
                        if (last?.msg === scanObj.current_phase) return prev
                        return [{ msg: scanObj.current_phase, time: new Date().toLocaleTimeString() }, ...prev].slice(0, 50)
                    })
                }

                if (scanObj.status === 'completed') {
                    setTimeout(() => navigate(`/results/${id}`), 1500)
                }
            } catch (e) {
                console.error(e)
            } finally {
                setLoading(false)
            }
        }

        fetchScanData()
        const interval = setInterval(fetchScanData, 3000)
        return () => clearInterval(interval)
    }, [id, navigate])
    
    const handleStopScan = async () => {
        if (!window.confirm("🚨 Are you sure you want to TERMINATE this scan session?")) return;
        try {
            const resp = await fetch(`${API}/scans/${id}/stop`, {
                method: 'POST'
            });
            if (resp.ok) {
                setScan(prev => ({ ...prev, status: 'stopped' }));
                setActivity(prev => [{ msg: '🛑 Scan stopped by user', time: new Date().toLocaleTimeString() }, ...prev]);
            }
        } catch (e) {
            console.error("Failed to stop scan:", e);
        }
    }

    useEffect(() => {
        logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, [logs])

    if (loading) return (
        <div className="flex items-center justify-center min-h-[60vh]">
            <div className="text-center">
                <div className="w-14 h-14 border-4 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
                <p className="text-gray-400">Loading scan…</p>
            </div>
        </div>
    )

    if (!scan) return <div className="text-center p-16 text-gray-500">Scan not found.</div>

    const progress = scan.progress || 0
    const isRunning = scan.status === 'running' || scan.status === 'pending'
    const isFailed = scan.status === 'failed'
    const isStopped = scan.status === 'stopped'
    const isCompleted = scan.status === 'completed'
    const sevCounts = findings.reduce((a, f) => { a[f.severity] = (a[f.severity] || 0) + 1; return a }, {})
    const elapsed = scan.created_at ? Math.floor((Date.now() - new Date(scan.created_at).getTime()) / 1000) : 0
    const elapsedStr = elapsed < 60 ? `${elapsed}s` : `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`

    return (
        <div className="max-w-6xl mx-auto px-4 pb-10">
            {/* Header */}
            <div className="flex items-start justify-between mb-6">
                <div>
                    <h1 className="text-3xl font-bold text-gradient">Live Scan</h1>
                    <p className="text-gray-400 mt-1">{scan.target_url}</p>
                </div>
                <div className="flex items-center space-x-3">
                    <div className="flex items-center space-x-1.5 text-sm text-gray-400">
                        <Clock size={13} /><span>{elapsedStr}</span>
                    </div>
                    {isRunning && (
                        <div className="flex items-center space-x-2">
                             <span className="flex items-center space-x-1.5 text-sm font-semibold text-blue-400 bg-blue-900/30 px-3 py-1 rounded-full border border-blue-700/40 animate-pulse">
                                <span className="w-2 h-2 bg-blue-400 rounded-full" /><span>SCANNING</span>
                            </span>
                            <button 
                                onClick={handleStopScan}
                                className="flex items-center space-x-1.5 text-xs font-bold text-red-400 bg-red-900/20 hover:bg-red-500 hover:text-white px-3 py-1 rounded-full border border-red-500/30 transition-all uppercase tracking-tighter"
                            >
                                <span>Stop</span>
                            </button>
                        </div>
                    )}
                    {isFailed && <span className="text-sm font-semibold text-red-400 bg-red-900/30 px-3 py-1 rounded-full border border-red-700/40">FAILED</span>}
                    {isStopped && <span className="text-sm font-semibold text-gray-400 bg-gray-900/30 px-3 py-1 rounded-full border border-gray-800/40 uppercase tracking-widest">Stopped</span>}
                    {isCompleted && (
                        <span className="text-sm font-semibold text-green-400 bg-green-900/30 px-3 py-1 rounded-full border border-green-700/40 flex items-center space-x-1">
                            <CheckCircle2 size={13} /><span>COMPLETED — redirecting…</span>
                        </span>
                    )}
                </div>
            </div>

            {/* Phase Progress Bar */}
            <div className="bg-gray-900 rounded-xl border border-gray-800 p-6 mb-6">
                <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold text-white">Scan Progress</h3>
                    <span className="text-xl font-bold text-gradient">{progress}%</span>
                </div>
                <PhaseBar
                    progress={progress}
                    isRunning={isRunning}
                    currentPhase={scan.current_phase}
                    scanType={scan.scan_type}
                    selectedPhase={selectedPhase}
                    onPhaseSelect={setSelectedPhase}
                />
            </div>

            {/* Detailed Phase Findings */}
            {selectedPhase && (
                <div className="bg-gray-950/40 backdrop-blur-xl border border-gray-800/50 rounded-2xl p-8 mb-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h2 className="text-2xl font-bold text-white flex items-center space-x-3">
                                <span className="text-3xl">{PHASES.find(p => p.id === selectedPhase)?.icon}</span>
                                <span>{PHASES.find(p => p.id === selectedPhase)?.label} Details</span>
                            </h2>
                            <p className="text-sm text-gray-500 mt-1">{PHASES.find(p => p.id === selectedPhase)?.desc}</p>
                        </div>
                    </div>

                    {selectedPhase === 'port' && (
                        <div className="space-y-4">
                            {services.length === 0 ? (
                                <div className="p-12 text-center text-gray-600 border-2 border-dashed border-gray-800 rounded-2xl">
                                    No services detected yet.
                                </div>
                            ) : (
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {services.map(s => (
                                        <div key={s.id} className="bg-gray-900 border border-gray-800 rounded-xl p-5 hover:border-purple-500/50 transition-colors group">
                                            <div className="flex items-start justify-between">
                                                <div className="flex items-center space-x-4">
                                                    <div className="text-2xl font-black text-purple-500 bg-purple-500/10 px-3 py-1 rounded-lg">
                                                        {s.port}
                                                    </div>
                                                    <div>
                                                        <div className="font-bold text-white uppercase text-sm tracking-wider">{s.service_name}</div>
                                                        <div className="text-xs text-gray-400 mt-0.5">{s.protocol || 'tcp'} / {s.state || 'open'}</div>
                                                    </div>
                                                </div>
                                                {s.version && (
                                                    <div className="text-[10px] px-2 py-1 bg-gray-800 text-gray-300 rounded uppercase font-bold">
                                                        v {s.version}
                                                    </div>
                                                )}
                                            </div>
                                            {s.banner && (
                                                <div className="mt-4 p-3 bg-black/40 rounded border border-gray-800 text-xs font-mono text-gray-500 truncate group-hover:text-gray-300 transition-colors">
                                                    {s.banner}
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    )}

                    {selectedPhase === 'recon' && (
                        <div className="space-y-8">
                            {(!reconData || (!reconData.stats && !reconData.nodes)) ? (
                                <div className="p-12 text-center text-gray-600 border-2 border-dashed border-gray-800 rounded-2xl">
                                    Reconnaissance data is still being processed.
                                </div>
                            ) : (
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                    {/* Stats Card */}
                                    <div className="bg-blue-900/10 border border-blue-500/20 rounded-2xl p-6">
                                        <div className="text-xs font-bold text-blue-400 uppercase tracking-widest mb-4">Crawler Stats</div>
                                        <div className="grid grid-cols-2 gap-4">
                                            <div>
                                                <div className="text-2xl font-bold text-white">{reconData.stats?.total_nodes || 0}</div>
                                                <div className="text-[10px] text-gray-500 uppercase tracking-tighter">Nodes Found</div>
                                            </div>
                                            <div>
                                                <div className="text-2xl font-bold text-white">{reconData.stats?.total_edges || 0}</div>
                                                <div className="text-[10px] text-gray-500 uppercase tracking-tighter">Path Edges</div>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Tech Stack Card */}
                                    <div className="bg-purple-900/10 border border-purple-500/20 rounded-2xl p-6 md:col-span-2">
                                        <div className="text-xs font-bold text-purple-400 uppercase tracking-widest mb-4">Technology Fingerprint</div>
                                        <div className="flex flex-wrap gap-2">
                                            {/* Extract techs from metadata or stats if available, otherwise show fallback */}
                                            {scan.metadata?.technologies ? (
                                                Object.keys(scan.metadata.technologies).map(tech => (
                                                    <div key={tech} className="px-3 py-1.5 bg-purple-500/10 border border-purple-500/30 rounded-lg text-xs text-purple-200 font-medium">
                                                        {tech}
                                                    </div>
                                                ))
                                            ) : (
                                                <div className="text-sm text-gray-500 italic">Detecting...</div>
                                            )}
                                            {scan.metadata?.waf && (
                                                <div className="px-3 py-1.5 bg-orange-500/10 border border-orange-500/30 rounded-lg text-xs text-orange-200 font-bold">
                                                    🛡️ WAF: {scan.metadata.waf}
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {selectedPhase === 'owasp' && (
                        <div className="space-y-4">
                            {findings.length === 0 ? (
                                <div className="p-12 text-center text-gray-600 border-2 border-dashed border-gray-800 rounded-2xl">
                                    No OWASP vulnerabilities found yet.
                                </div>
                            ) : (
                                <div className="grid grid-cols-1 gap-3">
                                    {findings.map((f, i) => (
                                        <div key={f.id || i} className="bg-gray-900/40 border border-gray-800 rounded-xl p-4 flex items-center justify-between hover:bg-gray-800/40 transition-colors">
                                            <div className="flex items-center space-x-4">
                                                <SeverityBadge severity={f.severity} />
                                                <div>
                                                    <div className="font-bold text-white text-sm">{f.name}</div>
                                                    <div className="text-xs text-gray-500 mt-0.5">{f.url}</div>
                                                </div>
                                            </div>
                                            <button className="p-2 text-gray-500 hover:text-purple-400 transition-colors">
                                                <ExternalLink size={16} />
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    )}

                    {(selectedPhase === 'cve' || selectedPhase === 'report') && (
                        <div className="p-16 text-center text-gray-500 border-2 border-dashed border-gray-800 rounded-2xl italic">
                            Detailed results for this phase will be available upon completion.
                        </div>
                    )}
                </div>
            )}

            {/* Live findings + stats row */}
            <div className="grid grid-cols-3 gap-5">
                {/* Severity counters */}
                <div className="col-span-1 space-y-3">
                    {[
                        { label: 'Critical', color: '#ef4444', count: sevCounts.critical || sevCounts.Critical || 0 },
                        { label: 'High', color: '#f97316', count: sevCounts.high || sevCounts.High || 0 },
                        { label: 'Medium', color: '#eab308', count: sevCounts.medium || sevCounts.Medium || 0 },
                        { label: 'Low', color: '#3b82f6', count: sevCounts.low || sevCounts.Low || 0 },
                        { label: 'Info', color: '#8b5cf6', count: sevCounts.info || sevCounts.Info || 0 },
                    ].map(({ label, color, count }) => (
                        <div key={label} className="bg-gray-900 border border-gray-800 rounded-xl p-4 flex items-center justify-between">
                            <span className="text-sm text-gray-400">{label}</span>
                            <span className="text-2xl font-bold" style={{ color }}>{count}</span>
                        </div>
                    ))}
                </div>

                {/* Live findings stream */}
                <div className="col-span-1 bg-gray-900 border border-gray-800 rounded-xl overflow-hidden flex flex-col">
                    <div className="px-5 py-4 border-b border-gray-800 flex items-center justify-between">
                        <h3 className="font-semibold text-white">Findings</h3>
                        <span className="text-xs text-gray-500">{findings.length} total</span>
                    </div>
                    <div className="flex-1 max-h-[420px] overflow-y-auto divide-y divide-gray-800">
                        {findings.length === 0 ? (
                            <div className="p-8 text-center text-gray-600 text-sm">No findings yet…</div>
                        ) : (
                            [...findings].reverse().map((f, i) => (
                                <div key={f.id || i} className="flex items-start space-x-3 px-4 py-3 hover:bg-gray-800/40 transition-colors">
                                    <SeverityBadge severity={f.severity} size="sm" />
                                    <div className="flex-1 min-w-0">
                                        <p className="text-sm font-medium text-white truncate">{f.name}</p>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>

                {/* Activity Log */}
                <div className="col-span-1 bg-gray-900 border border-gray-800 rounded-xl overflow-hidden flex flex-col">
                    <div className="px-5 py-4 border-b border-gray-800">
                        <h3 className="font-semibold text-white">Activity Log</h3>
                    </div>
                    <div className="flex-1 max-h-[420px] overflow-y-auto p-4 space-y-3 font-mono text-[11px]">
                        {activity.length === 0 ? (
                            <div className="text-center text-gray-600 py-10 italic">Initializing engine…</div>
                        ) : (
                            activity.map((a, i) => (
                                <div key={i} className="flex items-start space-x-2 border-l-2 border-gray-800 pl-3">
                                    <span className="text-gray-600 flex-shrink-0">{a.time}</span>
                                    <span className="text-purple-400 font-bold shrink-0">::</span>
                                    <span className="text-gray-300 leading-relaxed">{a.msg}</span>
                                </div>
                            ))
                        )}
                        <div ref={logsEndRef} />
                    </div>
                </div>
            </div>
        </div>
    )
}

export default LiveScan
