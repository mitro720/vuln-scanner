import { useState, useEffect } from 'react'
import { Bot, X, Zap, Shield, Code, ChevronDown, Copy, CheckCircle2, RotateCcw, AlertTriangle, Terminal, Rocket, ExternalLink, Globe } from 'lucide-react'

const API_BASE = 'http://localhost:5000/api'

/* ── Markdown Renderer (Optimized for Remediation) ────────────────────── */
const Markdown = ({ text }) => {
    const lines = (text || '').split('\n')
    const elements = []
    let codeBuffer = [], inCode = false, codeLang = ''

    lines.forEach((line, i) => {
        if (line.startsWith('```')) {
            if (inCode) {
                elements.push(
                    <div key={`code-${i}`} className="group relative my-4">
                        <div className="absolute top-0 right-0 p-2 flex items-center space-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
                            <button 
                                onClick={() => { navigator.clipboard.writeText(codeBuffer.join('\n')); alert('Code copied!') }}
                                className="p-1.5 bg-gray-800/80 hover:bg-gray-700 rounded-lg text-white border border-gray-600 backdrop-blur-sm shadow-xl"
                            >
                                <Copy size={14} />
                            </button>
                        </div>
                        <pre className="bg-gray-950 border border-gray-700/50 rounded-xl p-4 overflow-x-auto text-[13px] font-mono text-blue-300 leading-relaxed shadow-inner">
                            <code>{codeBuffer.join('\n')}</code>
                        </pre>
                    </div>
                )
                codeBuffer = []; inCode = false
            } else { inCode = true; codeLang = line.slice(3) }
            return
        }
        if (inCode) { codeBuffer.push(line); return }
        if (!line.trim()) { elements.push(<div key={i} className="h-4" />); return }

        const renderInline = str => {
            const parts = str.split(/(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g)
            return parts.map((p, j) => {
                if (p.startsWith('**') && p.endsWith('**')) return <strong key={j} className="font-bold text-white tracking-tight">{p.slice(2, -2)}</strong>
                if (p.startsWith('*') && p.endsWith('*')) return <em key={j} className="italic text-gray-300">{p.slice(1, -1)}</em>
                if (p.startsWith('`') && p.endsWith('`')) return <code key={j} className="bg-purple-900/30 px-1.5 py-0.5 rounded text-[13px] font-mono text-purple-300 border border-purple-500/20">{p.slice(1, -1)}</code>
                return p
            })
        }

        if (/^#{1,4} /.test(line)) {
            const level = line.match(/^#+/)[0].length
            const text = line.replace(/^#+ /, '')
            const cls = level === 1 ? 'text-xl font-bold text-white mb-4 mt-6 border-b border-gray-800 pb-2' 
                       : level === 2 ? 'text-lg font-bold text-purple-400 mb-3 mt-5' 
                       : 'text-sm font-bold text-gray-300 mb-2 mt-4 uppercase tracking-widest'
            elements.push(<p key={i} className={cls}>{renderInline(text)}</p>)
        } else if (/^[-*] /.test(line)) {
            elements.push(
                <div key={i} className="flex items-start space-x-3 text-[14px] text-gray-400 mb-2.5 leading-relaxed">
                    <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-purple-500/60 flex-shrink-0" />
                    <span>{renderInline(line.slice(2))}</span>
                </div>
            )
        } else if (/^\d+\. /.test(line)) {
            const n = line.match(/^\d+/)[0]
            elements.push(
                <div key={i} className="flex items-start space-x-3 text-[14px] text-gray-400 mb-2.5 leading-relaxed">
                    <span className="mt-0.5 font-bold text-purple-500 text-xs w-5">{n}.</span>
                    <span>{renderInline(line.replace(/^\d+\. /, ''))}</span>
                </div>
            )
        } else {
            elements.push(<p key={i} className="text-[14px] text-gray-400 leading-relaxed mb-3">{renderInline(line)}</p>)
        }
    })
    return <div className="pb-8">{elements}</div>
}

/* ── Remediation Hub Component ─────────────────────────────────────────── */
const RemediationHub = ({ isOpen, onClose, finding }) => {
    const [remediation, setRemediation] = useState('')
    const [loading, setLoading] = useState(false)
    const [techStack, setTechStack] = useState('Generic / Auto-detect')
    const [activeTab, setActiveTab] = useState('advisor')

    useEffect(() => {
        if (isOpen && finding && !remediation) {
            generateRemediation()
        }
    }, [isOpen, finding])

    const generateRemediation = async () => {
        if (!finding) return
        setLoading(true)
        setRemediation('')
        
        try {
            const settings = JSON.parse(localStorage.getItem('securescan_ai_settings') || '{}')
            const res = await fetch(`${API_BASE}/ai/remediate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    findingId: finding.id,
                    techStack: techStack !== 'Generic / Auto-detect' ? [techStack] : [],
                    provider: settings.provider,
                    apiKey: settings.apiKey,
                }),
            })
            const data = await res.json()
            setRemediation(data?.data?.remediation || '⚠️ I could not generate a fix for this finding. Please check your AI configuration.')
        } catch {
            setRemediation('⚠️ Error reaching AI backend. Ensure the server is running and your API key is valid.')
        } finally {
            setLoading(false)
        }
    }

    if (!isOpen) return null

    return (
        <div className="fixed inset-0 z-[100] flex justify-end overflow-hidden">
            {/* Backdrop */}
            <div className="absolute inset-0 bg-black/60 backdrop-blur-sm transition-opacity" onClick={onClose} />

            {/* Hub Panel */}
            <div className={`relative w-full max-w-2xl bg-gray-900 border-l border-gray-800 shadow-2xl flex flex-col h-full transform transition-transform duration-500 ease-out ${isOpen ? 'translate-x-0' : 'translate-x-full'}`}>
                
                {/* Header */}
                <div className="px-8 py-6 gradient-bg border-b border-purple-500/20 flex flex-col space-y-4">
                    <div className="flex items-center justify-between text-white">
                        <div className="flex items-center space-x-3">
                            <div className="p-2.5 bg-white/10 rounded-xl backdrop-blur-md border border-white/20">
                                <Bot size={24} className="text-white" />
                            </div>
                            <div>
                                <h2 className="text-xl font-bold tracking-tight">AI Remediation Advisor</h2>
                                <p className="text-xs text-purple-200 mt-0.5 uppercase tracking-widest font-bold opacity-80">Security Engineering Assistant</p>
                            </div>
                        </div>
                        <button onClick={onClose} className="p-2 hover:bg-white/10 rounded-full transition-colors">
                            <X size={20} />
                        </button>
                    </div>

                    {/* Finding Brief */}
                    {finding && (
                        <div className="bg-black/20 rounded-xl p-4 border border-white/10 backdrop-blur-sm">
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-purple-500/40 text-white uppercase border border-purple-400/30">Target Finding</span>
                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                                    finding.severity === 'Critical' ? 'bg-red-500/40 text-red-200' :
                                    finding.severity === 'High' ? 'bg-orange-500/40 text-orange-200' :
                                    'bg-yellow-500/40 text-yellow-200'
                                }`}>{finding.severity}</span>
                            </div>
                            <h3 className="text-sm font-bold text-white line-clamp-1">{finding.name}</h3>
                            <div className="flex items-center space-x-3 mt-2 text-xs text-gray-300">
                                <span className="flex items-center space-x-1"><Globe size={11} className="text-purple-300" /> <span className="truncate max-w-[200px]">{finding.url}</span></span>
                                {finding.owasp && <span className="flex items-center space-x-1"><Shield size={11} className="text-purple-300" /> <span>{finding.owasp}</span></span>}
                            </div>
                        </div>
                    )}
                </div>

                {/* Toolbar */}
                <div className="px-8 py-3 bg-gray-900 border-b border-gray-800 flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                        <div className="flex items-center space-x-2 bg-gray-800 rounded-lg p-1 border border-gray-700">
                            <button onClick={() => setActiveTab('advisor')} className={`px-3 py-1.5 text-xs font-bold rounded-md transition-all ${activeTab === 'advisor' ? 'bg-purple-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'}`}>Advisor</button>
                            <button onClick={() => setActiveTab('raw')} className={`px-3 py-1.5 text-xs font-bold rounded-md transition-all ${activeTab === 'raw' ? 'bg-purple-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'}`}>Evidence</button>
                        </div>
                        
                        <div className="h-6 w-px bg-gray-800" />

                        <div className="flex items-center space-x-2">
                            <span className="text-[10px] font-bold text-gray-500 uppercase">Tech Stack:</span>
                            <select 
                                value={techStack}
                                onChange={(e) => setTechStack(e.target.value)}
                                className="bg-gray-800 border border-gray-700 text-gray-300 text-xs rounded-lg px-2 py-1 outline-none hover:border-purple-500/50 transition-colors"
                            >
                                <option>Generic / Auto-detect</option>
                                <option>Node.js (Express)</option>
                                <option>Node.js (Next.js)</option>
                                <option>Python (Django)</option>
                                <option>Python (Flask)</option>
                                <option>C# (ASP.NET Core)</option>
                                <option>PHP (Laravel)</option>
                                <option>Java (Spring Boot)</option>
                                <option>React (Frontend only)</option>
                            </select>
                        </div>
                    </div>

                    <button 
                        onClick={generateRemediation}
                        disabled={loading}
                        className="flex items-center space-x-2 text-xs font-bold text-purple-400 hover:text-purple-300 disabled:opacity-50 transition-colors"
                    >
                        <RotateCcw size={14} className={loading ? 'animate-spin' : ''} />
                        <span>Regenerate</span>
                    </button>
                </div>

                {/* Content */}
                <div className="flex-1 overflow-y-auto custom-scrollbar bg-[radial-gradient(circle_at_top_right,_var(--tw-gradient-stops))] from-purple-900/5 via-gray-900 to-gray-900 px-8 py-6">
                    {loading ? (
                        <div className="flex flex-col items-center justify-center h-full space-y-6 text-center">
                            <div className="relative">
                                <div className="w-20 h-20 border-4 border-purple-500/20 border-t-purple-500 rounded-full animate-spin" />
                                <Bot size={28} className="absolute inset-0 m-auto text-purple-500 animate-pulse" />
                            </div>
                            <div>
                                <h3 className="text-lg font-bold text-white mb-2">Analyzing Vulnerability...</h3>
                                <p className="text-sm text-gray-500 max-w-xs mx-auto leading-relaxed">My neural engine is drafting a custom security patch for your tech stack. One moment please.</p>
                            </div>
                        </div>
                    ) : (
                        <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
                            {activeTab === 'advisor' ? (
                                <Markdown text={remediation} />
                            ) : (
                                <div className="space-y-6">
                                    <div>
                                        <h3 className="text-sm font-bold text-gray-300 mb-3 flex items-center space-x-2">
                                            <Terminal size={16} className="text-blue-400" />
                                            <span>Scan Evidence</span>
                                        </h3>
                                        <pre className="bg-gray-950 border border-gray-800 rounded-xl p-5 text-xs text-green-400 font-mono overflow-auto max-h-[250px] leading-relaxed">
                                            {finding?.evidence || 'No evidence captured.'}
                                        </pre>
                                    </div>
                                    <div>
                                        <h3 className="text-sm font-bold text-gray-300 mb-3 flex items-center space-x-2">
                                            <Rocket size={16} className="text-pink-400" />
                                            <span>Proof of Concept</span>
                                        </h3>
                                        <div className="bg-gray-950 border border-gray-800 rounded-xl p-5">
                                            <code className="text-xs text-blue-300 font-mono break-all leading-relaxed">
                                                {finding?.poc || 'No PoC available.'}
                                            </code>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                </div>

                {/* Footer Actions */}
                <div className="px-8 py-4 bg-gray-950/50 border-t border-gray-800 backdrop-blur-md flex items-center justify-between">
                    <div className="flex items-center space-x-2 text-[11px] text-gray-500 italic">
                        <AlertTriangle size={12} className="text-yellow-600" />
                        <span>AI fixes should always be verified in a staging environment.</span>
                    </div>
                    <div className="flex space-x-3">
                        <button 
                            onClick={() => { window.print(); }}
                            className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-xs font-bold transition-all border border-gray-700"
                        >
                            Save as PDF
                        </button>
                        <button 
                            onClick={() => { navigator.clipboard.writeText(remediation); alert('Full remediation plan copied!') }}
                            className="px-4 py-2 gradient-bg text-white rounded-lg text-xs font-bold transition-all shadow-lg shadow-purple-500/20 active:scale-95"
                        >
                            Copy Full Plan
                        </button>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default RemediationHub
