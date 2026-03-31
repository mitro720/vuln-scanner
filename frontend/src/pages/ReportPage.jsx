import { useState, useEffect, useRef } from 'react'
import { useParams, Link } from 'react-router-dom'
import { Download, Printer, Shield, ArrowLeft, Globe, Clock, Bot, Sparkles, Loader2, Target, AlertTriangle, CheckCircle2, Info, Activity, FileText } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell, PieChart, Pie } from 'recharts'
import { format } from 'date-fns'

const API = 'http://localhost:5000/api'
const SEVERITY_COLORS = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#3b82f6', Info: '#8b5cf6' }
const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 }

const getRiskScore = (findings) => {
    const c = findings.filter(f => f.severity === 'Critical' || f.severity === 'critical').length * 10
    const h = findings.filter(f => f.severity === 'High' || f.severity === 'high').length * 7
    const m = findings.filter(f => f.severity === 'Medium' || f.severity === 'medium').length * 4
    const l = findings.filter(f => f.severity === 'Low' || f.severity === 'low').length * 1
    return Math.min((c + h + m + l) / 20, 10).toFixed(1)
}

const getRiskLabel = (score) => {
    if (score >= 9) return { label: 'CRITICAL RISK', color: '#ef4444', grade: 'F' }
    if (score >= 7) return { label: 'HIGH RISK', color: '#f97316', grade: 'D' }
    if (score >= 5) return { label: 'MEDIUM RISK', color: '#eab308', grade: 'C' }
    if (score >= 3) return { label: 'LOW RISK', color: '#3b82f6', grade: 'B' }
    return { label: 'STABLE / SECURE', color: '#22c55e', grade: 'A' }
}

const getSecurityGrade = (findings) => {
    const score = Number(getRiskScore(findings))
    return getRiskLabel(score).grade
}

const SevBadge = ({ sev }) => {
    const color = SEVERITY_COLORS[sev] || SEVERITY_COLORS[sev?.charAt(0).toUpperCase() + sev?.slice(1)] || '#8b5cf6'
    return (
        <span style={{ color, background: color + '20', border: `1px solid ${color}55` }}
            className="text-xs font-bold px-2 py-0.5 rounded">
            {sev}
        </span>
    )
}

const ReportPage = () => {
    const { id } = useParams()
    const [scan, setScan] = useState(null)
    const [findings, setFindings] = useState([])
    const [loading, setLoading] = useState(true)
    const [aiSummary, setAiSummary] = useState('')
    const [aiLoading, setAiLoading] = useState(false)
    const reportRef = useRef()

    useEffect(() => {
        const load = async () => {
            try {
                const [sRes, fRes] = await Promise.all([
                    fetch(`${API}/scans/${id}`),
                    fetch(`${API}/scans/${id}/findings`),
                ])
                const sData = await sRes.json()
                const fData = await fRes.json()
                
                const rawScan = sData.data || sData
                if (typeof rawScan.metadata === 'string') {
                    try { rawScan.metadata = JSON.parse(rawScan.metadata) } catch(e) { rawScan.metadata = {} }
                }

                setScan(rawScan)
                const rawFindings = (fData.data || fData || []).map(f => {
                    let evidence = f.evidence || '';
                    let poc_screenshot = null;
                    let alert_captured = null;

                    if (typeof evidence === 'string' && evidence.startsWith('{')) {
                        try {
                            const parsed = JSON.parse(evidence);
                            evidence = parsed.raw || evidence;
                            poc_screenshot = parsed.poc_screenshot;
                            alert_captured = parsed.alert_captured;
                        } catch (e) {}
                    } else if (typeof evidence === 'object' && evidence !== null) {
                        poc_screenshot = f.evidence.poc_screenshot;
                        alert_captured = f.evidence.alert_captured;
                        evidence = f.evidence.raw || JSON.stringify(f.evidence, null, 2);
                    }

                    return { ...f, evidence, poc_screenshot, alert_captured }
                })

                setFindings(
                    rawFindings.sort((a, b) =>
                    ((SEVERITY_ORDER[a.severity] ?? SEVERITY_ORDER[a.severity?.charAt(0).toUpperCase() + a.severity?.slice(1)] ?? 5)
                        - (SEVERITY_ORDER[b.severity] ?? SEVERITY_ORDER[b.severity?.charAt(0).toUpperCase() + b.severity?.slice(1)] ?? 5))
                    )
                )
            } catch (e) { console.error(e) }
            finally { setLoading(false) }
        }
        load()
    }, [id])

    const generateAISummary = async () => {
        setAiLoading(true)
        try {
            const aiSettings = JSON.parse(localStorage.getItem('securescan_ai_settings') || '{}')
            const res = await fetch(`${API}/ai/summary`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    scanId: id,
                    provider: aiSettings.provider,
                    apiKey: aiSettings.apiKey
                }),
            })
            const data = await res.json()
            if (data.success) {
                setAiSummary(data.data.summary)
            }
        } catch (e) { console.error(e) }
        finally { setAiLoading(false) }
    }

    const printReport = () => { window.print() }

    const exportPDF = async () => {
        const { default: jsPDF } = await import('jspdf')
        const { default: html2canvas } = await import('html2canvas')
        const canvas = await html2canvas(reportRef.current, { backgroundColor: '#fff', scale: 1.5 })
        const img = canvas.toDataURL('image/png')
        const pdf = new jsPDF({ orientation: 'portrait', unit: 'px', format: 'a4' })
        const w = pdf.internal.pageSize.getWidth()
        const h = pdf.internal.pageSize.getHeight()
        const iH = (canvas.height * w) / canvas.width
        let offset = 0
        while (offset < iH) {
            if (offset > 0) pdf.addPage()
            pdf.addImage(img, 'PNG', 0, -offset, w, iH)
            offset += h
        }
        pdf.save(`SecureScan-Report-${id}.pdf`)
    }

    if (loading) return <div className="text-center py-20 text-gray-400">Loading report…</div>
    if (!scan) return <div className="text-center py-20 text-gray-500">Report not found.</div>

    const riskScore = getRiskScore(findings)
    const riskInfo = getRiskLabel(Number(riskScore))
    const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }
    findings.forEach(f => {
        const s = f.severity?.charAt(0).toUpperCase() + f.severity?.slice(1)
        if (s in sevCounts) sevCounts[s]++
    })

    return (
        <>
            {/* Toolbar (hidden when printing) */}
            <div className="max-w-4xl mx-auto px-4 mb-6 flex items-center justify-between no-print">
                <Link to={`/results/${id}`} className="flex items-center space-x-2 text-gray-400 hover:text-white transition-colors text-sm">
                    <ArrowLeft size={15} /><span>Back to Results</span>
                </Link>
                <div className="flex space-x-3">
                    <button onClick={printReport} className="flex items-center space-x-2 px-4 py-2 border border-gray-700 text-gray-300 rounded-lg hover:bg-gray-800 text-sm transition-colors">
                        <Printer size={15} /><span>Print</span>
                    </button>
                    <button onClick={exportPDF} className="flex items-center space-x-2 px-4 py-2 gradient-bg text-white rounded-lg hover:shadow-lg hover:shadow-purple-500/20 text-sm transition-all">
                        <Download size={15} /><span>Export PDF</span>
                    </button>
                </div>
            </div>

            {/* Report Body (white for printing) */}
            <div ref={reportRef} className="max-w-4xl mx-auto px-4 pb-10 font-sans text-slate-900 bg-white">
                {/* ── Cover Page ────────────────────────────────────────── */}
                <div className="relative border-b-8 border-slate-900 mb-12 print:mb-8 bg-white min-h-[400px] flex flex-col justify-end">
                    {/* Confidential Watermark */}
                    <div className="absolute top-10 right-10 flex flex-col items-end opacity-20 pointer-events-none">
                        <span className="text-4xl font-black text-slate-300 uppercase leading-none">Confidential</span>
                        <span className="text-xs font-bold text-slate-400 mt-1 uppercase tracking-widest">Internal Security Audit</span>
                    </div>

                    {/* Branding Bar */}
                    <div className="absolute top-0 left-0 w-full h-[120px] bg-slate-900 flex items-center px-12">
                        <div className="flex items-center space-x-4 text-white">
                            <div className="p-3 bg-purple-600 rounded-lg">
                                <Shield size={32} />
                            </div>
                            <div>
                                <h1 className="text-2xl font-black tracking-tight leading-none uppercase">SecureScan</h1>
                                <p className="text-[10px] text-purple-300 font-bold tracking-[0.2em] mt-1 uppercase">Advanced Infrastructure Intelligence</p>
                            </div>
                        </div>
                    </div>

                    <div className="px-12 pb-12 pt-40">
                        <div className="grid grid-cols-12 gap-8 items-end">
                            <div className="col-span-8">
                                <span className="inline-block px-3 py-1 bg-red-100 text-red-700 text-[10px] font-black uppercase tracking-widest mb-4 border border-red-200">Official Finding Report</span>
                                <h2 className="text-5xl font-black text-slate-900 leading-tight tracking-tighter mb-6">{scan.target_url}</h2>
                                
                                <div className="flex flex-wrap gap-x-8 gap-y-4">
                                    <div className="flex items-center space-x-2">
                                        <div className="p-2 bg-slate-100 rounded-md text-slate-600"><Clock size={16} /></div>
                                        <div>
                                            <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Assessment Date</p>
                                            <p className="text-sm font-bold text-slate-700">{format(new Date(scan.created_at), 'MMMM dd, yyyy')}</p>
                                        </div>
                                    </div>
                                    <div className="flex items-center space-x-2">
                                        <div className="p-2 bg-slate-100 rounded-md text-slate-600"><Globe size={16} /></div>
                                        <div>
                                            <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Target Domain</p>
                                            <p className="text-sm font-bold text-slate-700">{new URL(scan.target_url).hostname}</p>
                                        </div>
                                    </div>
                                    <div className="flex items-center space-x-2">
                                        <div className="p-2 bg-slate-100 rounded-md text-slate-600"><Activity size={16} /></div>
                                        <div>
                                            <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Audit Protocol</p>
                                            <p className="text-sm font-bold text-slate-700 capitalize">{scan.scan_type || 'Full'} Vulnerability Scan</p>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div className="col-span-4 flex flex-col items-center">
                                <div className="relative group">
                                    <div className="w-32 h-32 rounded-3xl border-[10px] flex flex-col items-center justify-center bg-slate-50 transition-transform duration-500 group-hover:scale-105" style={{ borderColor: riskInfo.color }}>
                                        <span className="text-[10px] font-black text-slate-400 mb-[-4px] uppercase tracking-widest">Grade</span>
                                        <span className="text-6xl font-black" style={{ color: riskInfo.color }}>{riskInfo.grade}</span>
                                    </div>
                                    <div className="absolute -bottom-3 -right-3 w-10 h-10 bg-slate-900 rounded-xl flex items-center justify-center text-white border-2 border-white shadow-xl">
                                        <Target size={18} />
                                    </div>
                                </div>
                                <p className="mt-4 text-xs font-black tracking-widest uppercase opacity-80" style={{ color: riskInfo.color }}>Posturical Health Assessment</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="px-12 space-y-12">

                    {/* Executive Summary & Analytics */}
                    <div className="space-y-8">
                        <div>
                            <div className="flex items-center justify-between mb-6">
                                <div className="flex items-center space-x-3">
                                    <div className="p-2 bg-slate-100 rounded-lg text-slate-800"><FileText size={20} /></div>
                                    <h3 className="text-xl font-black text-slate-900 uppercase tracking-tight">Executive Summary</h3>
                                </div>
                                <button
                                    onClick={generateAISummary}
                                    disabled={aiLoading}
                                    className="no-print flex items-center space-x-2 px-4 py-2 bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 transition-all text-xs font-bold disabled:opacity-50 shadow-lg shadow-indigo-600/20"
                                >
                                    {aiLoading ? <Loader2 size={14} className="animate-spin" /> : <Bot size={14} />}
                                    <span>{aiSummary ? 'Regenerate Analysis' : 'Run AI Analysis'}</span>
                                </button>
                            </div>

                            <div className="grid grid-cols-5 gap-3 mb-8">
                                {Object.entries(sevCounts).map(([sev, count]) => (
                                    <div key={sev} className="relative overflow-hidden group border-2 rounded-2xl p-4 transition-all hover:bg-slate-50" style={{ borderColor: SEVERITY_COLORS[sev] + '40' }}>
                                        <div className="absolute top-0 right-0 p-2 opacity-10 group-hover:opacity-20 transition-opacity">
                                            <AlertTriangle size={32} style={{ color: SEVERITY_COLORS[sev] }} />
                                        </div>
                                        <div className="text-3xl font-black mb-1" style={{ color: SEVERITY_COLORS[sev] }}>{count}</div>
                                        <div className="text-[10px] font-black text-slate-400 uppercase tracking-widest">{sev}</div>
                                    </div>
                                ))}
                            </div>

                            {/* Analytics Grid */}
                            <div className="grid grid-cols-2 gap-8 mb-8">
                                <div className="bg-slate-50 rounded-3xl p-6 border border-slate-100">
                                    <h4 className="text-xs font-black text-slate-400 uppercase tracking-widest mb-6 flex items-center space-x-2">
                                        <Activity size={14} className="text-indigo-500" />
                                        <span>Severity Distribution</span>
                                    </h4>
                                    <div className="h-[200px] w-full">
                                        <ResponsiveContainer width="100%" height="100%">
                                            <BarChart data={Object.entries(sevCounts).map(([name, value]) => ({ name, value, fill: SEVERITY_COLORS[name] }))}>
                                                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                                                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fontSize: 10, fontWeight: 700, fill: '#64748b' }} />
                                                <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 10, fontWeight: 700, fill: '#64748b' }} />
                                                <Tooltip 
                                                    cursor={{ fill: '#f1f5f9' }}
                                                    contentStyle={{ borderRadius: '12px', border: 'none', boxShadow: '0 10px 15px -3px rgb(0 0 0 / 0.1)', fontSize: '12px', fontWeight: 700 }}
                                                />
                                                <Bar dataKey="value" radius={[4, 4, 0, 0]} barSize={30}>
                                                    {Object.entries(sevCounts).map((entry, index) => (
                                                        <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry[0]]} />
                                                    ))}
                                                </Bar>
                                            </BarChart>
                                        </ResponsiveContainer>
                                    </div>
                                </div>

                                <div className="bg-slate-50 rounded-3xl p-6 border border-slate-100 flex flex-col items-center justify-center text-center">
                                    <h4 className="text-xs font-black text-slate-400 uppercase tracking-widest mb-6 flex items-center space-x-2 self-start">
                                        <Target size={14} className="text-indigo-500" />
                                        <span>Vulnerability Density</span>
                                    </h4>
                                    <div className="relative mb-4">
                                        <div className="w-32 h-32 rounded-full border-[12px] border-slate-200 flex items-center justify-center">
                                            <div className="flex flex-col items-center">
                                                <span className="text-3xl font-black text-slate-800">{findings.length}</span>
                                                <span className="text-[8px] font-black text-slate-400 uppercase tracking-tighter">Total Issues</span>
                                            </div>
                                        </div>
                                        <div className="absolute top-0 right-0 w-8 h-8 bg-red-500 rounded-full flex items-center justify-center text-white border-2 border-white shadow-lg animate-pulse">
                                            <AlertTriangle size={14} />
                                        </div>
                                    </div>
                                    <p className="text-[11px] font-bold text-slate-500 max-w-[180px] leading-relaxed">
                                        Scan density indicates a <strong>{riskScore > 7 ? 'High' : 'Moderate'}</strong> accumulation of security debt relative to target surface area.
                                    </p>
                                </div>
                            </div>

                            <div className="prose prose-sm max-w-none text-slate-600 leading-relaxed mb-6">
                                <p>
                                    This audit was conducted using the SecureScan protocol, identifying <strong>{findings.length} unique security findings</strong> across the targeted infrastructure. 
                                    The assessment indicates that <strong>{Math.round(((sevCounts.Critical + sevCounts.High) / findings.length) * 100) || 0}%</strong> of discovered vulnerabilities are categorized as high-impact (Critical/High), 
                                    representing immediate risk to organizational assets.
                                </p>
                            </div>

                            {/* AI Summary Section */}
                            {aiSummary ? (
                                <div className="bg-slate-900 rounded-[2rem] p-10 relative overflow-hidden text-white shadow-2xl">
                                    <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none">
                                        <Bot size={120} className="text-indigo-400" />
                                    </div>
                                    <div className="flex items-center space-x-3 mb-6 bg-indigo-500/20 w-fit px-4 py-2 rounded-xl border border-indigo-500/30">
                                        <Sparkles size={18} className="text-indigo-300" />
                                        <h4 className="font-bold text-xs uppercase tracking-widest text-indigo-100">AI Vulnerability Intelligence</h4>
                                    </div>
                                    <div className="prose prose-invert prose-sm max-w-none text-slate-300 prose-headings:text-white prose-strong:text-indigo-300 prose-p:leading-relaxed">
                                        <ReactMarkdown>{aiSummary}</ReactMarkdown>
                                    </div>
                                </div>
                            ) : (
                                <div className="bg-slate-50 border-2 border-dashed border-slate-200 rounded-[2rem] p-12 text-center group cursor-pointer hover:bg-slate-100/50 transition-colors no-print" onClick={generateAISummary}>
                                    <div className="w-16 h-16 bg-white rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-sm border border-slate-200 group-hover:scale-110 transition-transform">
                                        <Bot size={32} className="text-slate-400 group-hover:text-indigo-500 transition-colors" />
                                    </div>
                                    <h4 className="text-sm font-bold text-slate-900 mb-2 font-black uppercase tracking-tight">AI Assessment Missing</h4>
                                    <p className="text-xs text-slate-500 max-w-xs mx-auto mb-6">Click to generate a deep-dive executive summary using our advanced security intelligence engine.</p>
                                    <button className="px-6 py-2.5 bg-slate-900 text-white rounded-xl text-xs font-bold hover:shadow-xl transition-shadow flex items-center space-x-2 mx-auto">
                                        <activity size={14} />
                                        <span>Initialize AI Engine</span>
                                    </button>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Discovery Metadata */}
                    <div className="space-y-6">
                        <div className="flex items-center space-x-3">
                            <div className="p-2 bg-slate-100 rounded-lg text-slate-800"><Activity size={20} /></div>
                            <h3 className="text-xl font-black text-slate-900 uppercase tracking-tight">Discovery Intelligence</h3>
                        </div>
                        <div className="grid grid-cols-3 gap-6">
                            <div className="col-span-1 bg-slate-50 rounded-2xl p-6 border border-slate-100">
                                <h4 className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-3">WAF Protection</h4>
                                <div className="flex items-center space-x-2">
                                    <Shield size={16} className={scan.metadata?.waf?.waf_detected ? "text-green-600" : "text-slate-400"} />
                                    <span className="text-sm font-bold">{scan.metadata?.waf?.waf_detected ? scan.metadata?.waf?.wafs?.join(', ') : 'No WAF Detected'}</span>
                                </div>
                            </div>
                            <div className="col-span-1 bg-slate-50 rounded-2xl p-6 border border-slate-100">
                                <h4 className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-3">Infrastructure</h4>
                                <div className="flex items-center space-x-2">
                                    <Globe size={16} className="text-slate-400" />
                                    <span className="text-sm font-bold text-slate-700">{scan.metadata?.technologies?.server || 'Unknown'}</span>
                                </div>
                            </div>
                            <div className="col-span-1 bg-slate-50 rounded-2xl p-6 border border-slate-100">
                                <h4 className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-3">Surface Area</h4>
                                <div className="flex items-center space-x-2">
                                    <Target size={16} className="text-slate-400" />
                                    <span className="text-sm font-bold text-slate-700">{scan.metadata?.ports?.total_open || 0} Open Ports</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Findings Detail (Technical Appendix) */}
                    <div className="space-y-8">
                        <div className="flex items-center space-x-3">
                            <div className="p-2 bg-slate-100 rounded-lg text-slate-800"><ArrowLeft size={20} className="rotate-180" /></div>
                            <h3 className="text-xl font-black text-slate-900 uppercase tracking-tight">Technical Appendix</h3>
                        </div>
                        
                        {findings.length === 0 ? (
                            <div className="text-center py-20 bg-slate-50 rounded-3xl border-2 border-dashed border-slate-200">
                                <CheckCircle2 size={48} className="mx-auto mb-4 text-green-500 opacity-20" />
                                <h4 className="text-lg font-black text-slate-400 uppercase">Compliance Satisfied</h4>
                                <p className="text-xs text-slate-400">No vulnerabilities were identified during this audit cycle.</p>
                            </div>
                        ) : (
                            <div className="space-y-12">
                                {findings.map((f, i) => {
                                    const sev = f.severity?.charAt(0).toUpperCase() + f.severity?.slice(1)
                                    const color = SEVERITY_COLORS[sev] || '#8b5cf6'
                                    const rem = Array.isArray(f.remediation) ? f.remediation : (f.remediation?.split('\n') || []).filter(Boolean)
                                    return (
                                        <div key={f.id || i} className="page-break-inside-avoid">
                                            <div className="flex items-start justify-between mb-4">
                                                <div className="flex items-center space-x-4">
                                                    <div className="w-10 h-10 rounded-xl flex items-center justify-center font-black text-white shadow-lg" style={{ backgroundColor: color }}>
                                                        {i + 1}
                                                    </div>
                                                    <div>
                                                        <h4 className="text-lg font-black text-slate-900 leading-none">{f.name}</h4>
                                                        <div className="flex items-center space-x-2 mt-2">
                                                            <SevBadge sev={sev} />
                                                            <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">{f.owasp || 'General Security'}</span>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div className="text-right">
                                                    <div className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">Impact Score</div>
                                                    <div className="text-xl font-black" style={{ color }}>CVSS {f.cvss_score || 'N/A'}</div>
                                                </div>
                                            </div>

                                            <div className="grid grid-cols-4 gap-6 mb-4">
                                                <div className="col-span-3">
                                                    <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2">Technical Description</p>
                                                    <p className="text-sm text-slate-600 leading-relaxed bg-slate-50 p-4 rounded-2xl border border-slate-100">{f.description}</p>
                                                </div>
                                                <div className="col-span-1 space-y-4">
                                                    <div>
                                                        <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2">Remediation Effort</p>
                                                        <span className={`inline-block px-3 py-1 rounded-full text-[10px] font-black uppercase ${
                                                            sev === 'Critical' || sev === 'High' ? 'bg-orange-100 text-orange-700' : 'bg-green-100 text-green-700'
                                                        }`}>
                                                            {sev === 'Critical' ? 'Immediate' : sev === 'High' ? 'High' : 'Standard'}
                                                        </span>
                                                    </div>
                                                    <div>
                                                        <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2">Identified CWE</p>
                                                        <span className="text-xs font-mono font-bold text-slate-500">{f.cwe || 'N/A'}</span>
                                                    </div>
                                                </div>
                                            </div>

                                            <div className="mb-6">
                                                <div className="flex items-center justify-between mb-2">
                                                    <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Verified Endpoint</p>
                                                    {f.poc_screenshot && (
                                                        <span className="text-[9px] font-black text-blue-600 bg-blue-100 px-2 py-0.5 rounded-md uppercase tracking-tighter flex items-center space-x-1">
                                                            <Camera size={10} />
                                                            <span>Visual PoC Captured</span>
                                                        </span>
                                                    )}
                                                </div>
                                                <code className="block text-xs text-blue-600 bg-blue-50/50 px-4 py-3 rounded-xl font-mono border border-blue-100 break-all">{f.url}</code>
                                            </div>

                                            {f.poc_screenshot && (
                                                <div className="mb-6">
                                                    <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-3">Automated Proof-of-Concept Screenshot</p>
                                                    <div className="relative rounded-2xl border-2 border-slate-100 overflow-hidden bg-slate-50 shadow-sm max-w-[80%]">
                                                        <img 
                                                            src={`http://localhost:5000/screenshots/${f.poc_screenshot}`} 
                                                            alt="Proof of Concept" 
                                                            className="w-full h-auto"
                                                        />
                                                        {f.alert_captured && (
                                                            <div className="absolute top-4 left-4 bg-white/95 shadow-xl rounded-lg p-3 border border-slate-200 border-l-4 border-l-blue-500 max-w-[80%]">
                                                                <p className="text-[8px] font-black text-slate-400 uppercase mb-1">Browser Alert Intercepted</p>
                                                                <p className="text-[10px] text-slate-800 font-mono italic break-all">"{f.alert_captured}"</p>
                                                            </div>
                                                        )}
                                                    </div>
                                                </div>
                                            )}

                                            {rem.length > 0 && (
                                                <div className="bg-slate-50 rounded-2xl p-6 border border-slate-100">
                                                    <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-4">Strategic Remediation</p>
                                                    <ul className="space-y-3">
                                                        {rem.slice(0, 4).map((step, j) => (
                                                            <li key={j} className="text-sm text-slate-600 flex items-start space-x-3">
                                                                <div className="w-5 h-5 rounded-md bg-white border border-slate-200 flex items-center justify-center text-[10px] font-black text-slate-400 mt-0.5">{j + 1}</div>
                                                                <span>{step}</span>
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}
                                        </div>
                                    )
                                })}
                            </div>
                        )}
                    </div>

                    {/* Footer */}
                    <div className="border-t-2 border-slate-900 pt-8 flex items-center justify-between text-[10px] font-black text-slate-400 uppercase tracking-widest">
                        <div className="flex items-center space-x-4">
                            <span>Scan Ref: {id}</span>
                            <span className="w-1 h-1 bg-slate-300 rounded-full"></span>
                            <span>SecureScan Audit v2.0</span>
                        </div>
                        <div className="text-right">
                            Page 01 / 01
                        </div>
                    </div>
                </div>
            </div>

            {/* Print styles */}
            <style>{`
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;700;900&display=swap');
                
                @media print {
                    .no-print { display: none !important; }
                    body { background: white !important; -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
                    .page-break-inside-avoid { page-break-inside: avoid; }
                    @page { margin: 0; }
                    
                    /* Force background colors in print */
                    .bg-slate-900 { background-color: #0f172a !important; }
                    .bg-slate-50 { background-color: #f8fafc !important; }
                    .text-white { color: white !important; }
                }

                .font-sans { font-family: 'Inter', sans-serif !important; }
            `}</style>
        </>
    )
}

export default ReportPage
