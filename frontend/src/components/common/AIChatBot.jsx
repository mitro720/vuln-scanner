import { useState, useRef, useEffect } from 'react'
import { Bot, X, Send, Trash2, Zap, Shield, Code, ChevronDown } from 'lucide-react'

const API_BASE = 'http://localhost:5000/api'

/* ── Simple Markdown renderer (no extra deps) ─────────────────────────── */
const Markdown = ({ text }) => {
    const lines = (text || '').split('\n')
    const elements = []
    let codeBuffer = [], inCode = false, codeLang = ''

    lines.forEach((line, i) => {
        if (line.startsWith('```')) {
            if (inCode) {
                elements.push(
                    <pre key={`code-${i}`} className="bg-gray-950 border border-gray-700 rounded-lg p-3 my-2 overflow-x-auto text-xs font-mono text-green-300 leading-relaxed">
                        <code>{codeBuffer.join('\n')}</code>
                    </pre>
                )
                codeBuffer = []; inCode = false
            } else { inCode = true; codeLang = line.slice(3) }
            return
        }
        if (inCode) { codeBuffer.push(line); return }
        if (!line.trim()) { elements.push(<div key={i} className="h-2" />); return }

        // Bold + italic inline
        const renderInline = str => {
            const parts = str.split(/(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g)
            return parts.map((p, j) => {
                if (p.startsWith('**') && p.endsWith('**')) return <strong key={j} className="font-bold text-white">{p.slice(2, -2)}</strong>
                if (p.startsWith('*') && p.endsWith('*')) return <em key={j} className="italic">{p.slice(1, -1)}</em>
                if (p.startsWith('`') && p.endsWith('`')) return <code key={j} className="bg-gray-800 px-1 py-0.5 rounded text-xs font-mono text-yellow-300">{p.slice(1, -1)}</code>
                return p
            })
        }

        if (/^#{1,3} /.test(line)) {
            const level = line.match(/^#+/)[0].length
            const text = line.replace(/^#+ /, '')
            const cls = level === 1 ? 'text-base font-bold text-purple-300 mt-2' : level === 2 ? 'text-sm font-bold text-purple-200 mt-2' : 'text-xs font-bold text-gray-300 mt-1'
            elements.push(<p key={i} className={cls}>{renderInline(text)}</p>)
        } else if (/^[-*] /.test(line)) {
            elements.push(<li key={i} className="text-sm ml-3 list-disc list-inside text-gray-300">{renderInline(line.slice(2))}</li>)
        } else if (/^\d+\. /.test(line)) {
            const n = line.match(/^\d+/)[0]
            elements.push(<li key={i} className="text-sm ml-3 list-decimal list-inside text-gray-300">{renderInline(line.replace(/^\d+\. /, ''))}</li>)
        } else {
            elements.push(<p key={i} className="text-sm text-gray-300 leading-relaxed">{renderInline(line)}</p>)
        }
    })
    return <div className="space-y-0.5">{elements}</div>
}

/* ── Quick Prompt Chips ────────────────────────────────────────────────── */
const QUICK_PROMPTS = [
    { icon: '🔍', label: 'Explain this', prompt: 'Explain this vulnerability in simple terms and why it matters.' },
    { icon: '⚔️', label: 'Attack scenario', prompt: 'Describe a realistic attack scenario — how would an attacker exploit this vulnerability step by step?' },
    { icon: '🛠️', label: 'Fix it', prompt: 'Give me specific, actionable remediation steps with code examples to fix this vulnerability.' },
    { icon: '📊', label: 'CVSS breakdown', prompt: 'Break down the CVSS score for this vulnerability and explain each metric.' },
    { icon: '🏢', label: 'Business impact', prompt: 'What is the business impact and compliance risk of leaving this vulnerability unpatched?' },
]

/* ── Main Chatbot Component ─────────────────────────────────────────────── */
const AIChatBot = () => {
    const [isOpen, setIsOpen] = useState(false)
    const [messages, setMessages] = useState([
        { role: 'assistant', content: '👋 Hi! I\'m SecureScan AI — your vulnerability remediation advisor.\n\nShare a finding with me or ask anything about web security, CVEs, and remediation best practices.' }
    ])
    const [input, setInput] = useState('')
    const [loading, setLoading] = useState(false)
    const [activeFinding, setActiveFinding] = useState(null)
    const [isMinimized, setIsMinimized] = useState(false)
    const messagesEndRef = useRef(null)

    // Expose a global method for other components (e.g. Results) to inject findings
    useEffect(() => {
        window.__securescanAI = {
            openWithFinding: (finding) => {
                setActiveFinding(finding)
                setIsOpen(true)
                setIsMinimized(false)
                const ctx = `\n\n---\n*📌 Analyzing finding: **${finding.name}** (${finding.severity} — CVSS ${finding.cvss_score || 'N/A'})*\n\nWhat would you like to know about this vulnerability?`
                setMessages(prev => [
                    ...prev,
                    { role: 'assistant', content: ctx },
                ])
            }
        }
    }, [])

    useEffect(() => {
        if (isOpen && !isMinimized) messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, [messages, isOpen, isMinimized])

    const getAISettings = () => {
        try {
            return JSON.parse(localStorage.getItem('securescan_ai_settings') || '{}')
        } catch { return {} }
    }

    const sendMessage = async (text) => {
        const userMsg = text || input.trim()
        if (!userMsg || loading) return
        setInput('')

        const userMessages = [...messages, { role: 'user', content: userMsg }]
        setMessages(userMessages)
        setLoading(true)

        try {
            const settings = getAISettings()
            const res = await fetch(`${API_BASE}/ai/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    messages: userMessages.filter(m => m.role !== 'assistant' || messages.indexOf(m) > 0)
                        .map(m => ({ role: m.role, content: m.content })),
                    findingId: activeFinding?.id,
                    provider: settings.provider,
                    apiKey: settings.apiKey,
                }),
            })
            const data = await res.json()
            const reply = data?.data?.reply || '⚠️ No response from AI. Check your API key in Settings.'
            setMessages(prev => [...prev, { role: 'assistant', content: reply }])
        } catch {
            setMessages(prev => [...prev, { role: 'assistant', content: '⚠️ Could not reach the backend. Make sure the server is running.' }])
        } finally {
            setLoading(false)
        }
    }

    if (!isOpen) {
        return (
            <button onClick={() => setIsOpen(true)}
                className="fixed bottom-6 right-6 p-4 gradient-bg text-white rounded-full shadow-2xl hover:shadow-purple-500/40 transition-all transform hover:scale-110 z-50 flex items-center justify-center">
                <Bot size={26} />
            </button>
        )
    }

    return (
        <div className={`fixed bottom-6 right-6 w-[420px] bg-gray-900 rounded-2xl shadow-2xl flex flex-col z-50 overflow-hidden border border-gray-700 transition-all duration-300 ${isMinimized ? 'h-14' : 'h-[620px]'}`}>
            {/* Header */}
            <div className="gradient-bg px-4 py-3 flex items-center justify-between text-white flex-shrink-0 cursor-pointer" onClick={() => setIsMinimized(!isMinimized)}>
                <div className="flex items-center space-x-2">
                    <Bot size={20} />
                    <div>
                        <span className="font-bold text-sm">SecureScan AI</span>
                        {activeFinding && <span className="text-xs text-purple-200 ml-2">· {activeFinding.name?.slice(0, 25)}…</span>}
                    </div>
                </div>
                <div className="flex items-center space-x-1">
                    {activeFinding && (
                        <button onClick={e => { e.stopPropagation(); setActiveFinding(null) }}
                            className="text-xs px-2 py-0.5 bg-white/20 rounded hover:bg-white/30 transition-colors">
                            Clear finding
                        </button>
                    )}
                    <button onClick={e => { e.stopPropagation(); setMessages([messages[0]]); setActiveFinding(null) }}
                        className="p-1 hover:bg-white/20 rounded-full" title="Clear chat">
                        <Trash2 size={15} />
                    </button>
                    <button onClick={e => { e.stopPropagation(); setIsMinimized(!isMinimized) }}
                        className="p-1 hover:bg-white/20 rounded-full">
                        <ChevronDown size={15} className={`transition-transform ${isMinimized ? 'rotate-180' : ''}`} />
                    </button>
                    <button onClick={e => { e.stopPropagation(); setIsOpen(false) }}
                        className="p-1 hover:bg-white/20 rounded-full">
                        <X size={15} />
                    </button>
                </div>
            </div>

            {!isMinimized && (
                <>
                    {/* Messages */}
                    <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-gray-950">
                        {messages.map((msg, i) => (
                            <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                                {msg.role === 'assistant' && (
                                    <div className="w-6 h-6 rounded-full gradient-bg flex items-center justify-center flex-shrink-0 mt-1 mr-2">
                                        <Bot size={12} className="text-white" />
                                    </div>
                                )}
                                <div className={`max-w-[84%] rounded-2xl px-3.5 py-2.5 ${msg.role === 'user'
                                    ? 'gradient-bg text-white rounded-br-none'
                                    : 'bg-gray-800 border border-gray-700 rounded-bl-none'}`}>
                                    {msg.role === 'assistant'
                                        ? <Markdown text={msg.content} />
                                        : <p className="text-sm">{msg.content}</p>
                                    }
                                </div>
                            </div>
                        ))}
                        {loading && (
                            <div className="flex justify-start">
                                <div className="w-6 h-6 rounded-full gradient-bg flex items-center justify-center flex-shrink-0 mt-1 mr-2">
                                    <Bot size={12} className="text-white" />
                                </div>
                                <div className="bg-gray-800 border border-gray-700 rounded-2xl rounded-bl-none px-4 py-3 flex items-center space-x-1.5">
                                    {[0, 150, 300].map(d => (
                                        <div key={d} className="w-1.5 h-1.5 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: `${d}ms` }} />
                                    ))}
                                </div>
                            </div>
                        )}
                        <div ref={messagesEndRef} />
                    </div>

                    {/* Quick Prompts */}
                    <div className="flex gap-1.5 px-3 py-2 bg-gray-900 border-t border-gray-800 overflow-x-auto flex-shrink-0">
                        {QUICK_PROMPTS.map(qp => (
                            <button key={qp.label} onClick={() => sendMessage(qp.prompt)}
                                className="flex-shrink-0 flex items-center space-x-1 px-2.5 py-1 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-full text-xs text-gray-300 transition-colors">
                                <span>{qp.icon}</span><span>{qp.label}</span>
                            </button>
                        ))}
                    </div>

                    {/* Input */}
                    <form onSubmit={e => { e.preventDefault(); sendMessage() }} className="p-3 bg-gray-900 border-t border-gray-800 flex-shrink-0">
                        <div className="flex space-x-2">
                            <input type="text" value={input} onChange={e => setInput(e.target.value)}
                                placeholder="Ask about this vulnerability…"
                                className="flex-1 px-3 py-2 bg-gray-800 border border-gray-700 rounded-xl focus:outline-none focus:ring-1 focus:ring-purple-500 text-sm text-white placeholder-gray-500 transition-all" />
                            <button type="submit" disabled={!input.trim() || loading}
                                className="p-2 gradient-bg text-white rounded-xl hover:shadow-lg hover:shadow-purple-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all">
                                <Send size={16} />
                            </button>
                        </div>
                    </form>
                </>
            )}
        </div>
    )
}

export default AIChatBot
