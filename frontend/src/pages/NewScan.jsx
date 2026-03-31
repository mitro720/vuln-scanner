import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Zap, Search, Globe, Shield, Cpu, Check, ArrowRight, Loader2, Radar, Bug, Lock, Server, Activity } from 'lucide-react'

const MODULE_CATEGORIES = [
    {
        id: 'injection',
        name: '💉 Injection',
        desc: 'SQLi, NoSQL, Command, SSTI, etc.',
        modules: [
            { id: 'SQL Injection', label: 'SQL Injection' },
            { id: 'NoSQL Injection', label: 'NoSQL Injection' },
            { id: 'Command Injection', label: 'Command Injection' },
            { id: 'Server-Side Template Injection', label: 'SSTI' },
            { id: 'LDAP Injection', label: 'LDAP Injection' },
            { id: 'XXE', label: 'XXE (XML External Entity)' },
            { id: 'CRLF Injection', label: 'CRLF Injection' },
        ]
    },
    {
        id: 'auth',
        name: '🔐 Auth & Access',
        desc: 'IDOR, JWT, Bypass, Mass Assignment',
        modules: [
            { id: 'IDOR', label: 'IDOR (Insecure Direct Object Reference)' },
            { id: 'JWT', label: 'JWT Vulnerabilities' },
            { id: 'Mass Assignment', label: 'Mass Assignment' },
            { id: 'A01: Access Control', label: 'Broken Access Control' },
        ]
    },
    {
        id: 'config',
        name: '⚙️ Config & Crypto',
        desc: 'CORS, Headers, Rate Limiting',
        modules: [
            { id: 'CORS', label: 'CORS Misconfiguration' },
            { id: 'Host Header Injection', label: 'Host Header Injection' },
            { id: 'Rate Limit Bypass', label: 'Rate Limit Bypass' },
        ]
    },
    {
        id: 'web',
        name: '🌐 Web Flaws',
        desc: 'XSS, SSRF, GraphQL, Smuggling',
        modules: [
            { id: 'XSS', label: 'XSS (Reflected/Stored)' },
            { id: 'SSRF', label: 'SSRF (Server-Side Request Forgery)' },
            { id: 'GraphQL Abuse', label: 'GraphQL Abuse' },
            { id: 'Open Redirect', label: 'Open Redirect' },
            { id: 'HTTP Request Smuggling', label: 'Request Smuggling' },
        ]
    }
]

const NewScan = () => {
    const navigate = useNavigate()
    const API = 'http://localhost:5000/api'
    
    // Wizard State
    const [step, setStep] = useState(1) // 1: Setup, 2: Recon/Select, 3: Modules
    const [targetUrl, setTargetUrl] = useState('')
    const [scanId, setScanId] = useState(null)
    const [loading, setLoading] = useState(false)
    
    // Step 2 State (Recon)
    const [discoveredTargets, setDiscoveredTargets] = useState([])
    const [selectedTargets, setSelectedTargets] = useState([])
    const [reconProgress, setReconProgress] = useState(0)
    const [reconStatus, setReconStatus] = useState('pending')
    
    // Step 3 State (Modules)
    const [selectedModules, setSelectedModules] = useState(['SQL Injection', 'XSS', 'Command Injection', 'CORS'])
    const [customPayloads, setCustomPayloads] = useState('')
    
    // Auth State
    const [authConfig, setAuthConfig] = useState({
        enabled: false,
        login_url: '',
        username: '',
        password: '',
        username_field: 'username',
        password_field: 'password'
    })
    
    // Polling for Recon Results (Step 2)
    useEffect(() => {
        let interval
        if (step === 2 && scanId) {
            interval = setInterval(async () => {
                try {
                    // 1. Fetch findings to get subdomains
                    const userData = JSON.parse(localStorage.getItem('user') || '{}');
                    const token = userData?.token;
                    const headers = { 'Authorization': `Bearer ${token}` }
                    
                    const res = await fetch(`${API}/scans/${scanId}/findings`, { headers })
                    const data = await res.json()
                    let newTargets = [targetUrl]
                    
                    if (data.success) {
                        const subdomains = data.data
                            .filter(f => f.name === 'Live Subdomain Discovered')
                            .map(f => f.url)
                        newTargets.push(...subdomains)
                    }

                    // 2. Fetch crawl data for internal pages
                    const crawlRes = await fetch(`${API}/crawl/scan/${scanId}`, { headers })
                    const crawlData = await crawlRes.json()
                    if (crawlData.success && crawlData.data && crawlData.data.nodes) {
                        const pages = crawlData.data.nodes.map(n => n.id)
                        newTargets.push(...pages)
                    }
                    
                    setDiscoveredTargets([...new Set(newTargets)])
                    
                    // 3. Fetch scan status for progress
                    const sRes = await fetch(`${API}/scans/${scanId}`, { headers })
                    const sData = await sRes.json()
                    if (sData.success) {
                        setReconProgress(sData.data.progress)
                        if (sData.data.status === 'completed' || sData.data.progress > 30) {
                            setReconStatus('ready')
                        }
                    }
                } catch (e) {
                    console.error('Polling error:', e)
                }
            }, 3000)
        }
        return () => clearInterval(interval)
    }, [step, scanId, targetUrl])

    const startDiscovery = async () => {
        if (!targetUrl.trim()) return
        setLoading(true)
        const userData = JSON.parse(localStorage.getItem('user') || '{}');
        const token = userData?.token;
        try {
            const response = await fetch(`${API}/scans`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    target_url: targetUrl.trim(),
                    phase: 'recon', // Modular phase
                    config: { 
                        subdomain: true, 
                        tech: true, 
                        waf: true,
                        login_config: authConfig.enabled ? {
                            login_url: authConfig.login_url,
                            username: authConfig.username,
                            password: authConfig.password,
                            username_field: authConfig.username_field,
                            password_field: authConfig.password_field
                        } : null
                    }
                }),
            })
            if (response.ok) {
                const data = await response.json()
                setScanId(data.data.id)
                setStep(2)
                setSelectedTargets([targetUrl.trim()]) // Always include base target
            }
        } catch (err) {
            alert('Discovery failed: ' + err.message)
        } finally {
            setLoading(false)
        }
    }

    const launchFullScan = async () => {
        setLoading(true)
        const userData = JSON.parse(localStorage.getItem('user') || '{}');
        const token = userData?.token;
        try {
            const response = await fetch(`${API}/scans/${scanId}/continue`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    selected_targets: selectedTargets,
                    selected_modules: selectedModules,
                    custom_payloads: customPayloads.split('\n').filter(p => p.trim()),
                    login_config: authConfig.enabled ? {
                        login_url: authConfig.login_url,
                        username: authConfig.username,
                        password: authConfig.password,
                        username_field: authConfig.username_field,
                        password_field: authConfig.password_field
                    } : null
                }),
            })
            if (response.ok) {
                navigate(`/scan/${scanId}`)
            }
        } catch (err) {
            alert('Launch failed: ' + err.message)
        } finally {
            setLoading(false)
        }
    }

    return (
        <div className="max-w-5xl mx-auto px-4 pb-20">
            {/* Wizard Header */}
            <div className="mb-12 text-center">
                <h1 className="text-4xl font-black text-gradient mb-2 tracking-tight">SCAN WIZARD</h1>
                <p className="text-dark-text-secondary text-sm uppercase tracking-widest font-bold opacity-60">Interactive Orchestration</p>
                
                {/* Stepper UI */}
                <div className="flex items-center justify-center mt-8 space-x-4">
                    {[
                        { num: 1, label: 'Target', icon: Globe },
                        { num: 2, label: 'Discovery', icon: Search },
                        { num: 3, label: 'Attack Box', icon: Zap }
                    ].map((s) => (
                        <div key={s.num} className="flex items-center">
                            <div className={`
                                flex items-center justify-center w-10 h-10 rounded-full border-2 transition-all duration-500
                                ${step >= s.num ? 'border-primary-500 bg-primary-500/20 text-white shadow-lg shadow-primary-500/20' : 'border-white/10 text-white/30'}
                            `}>
                                {step > s.num ? <Check size={18} /> : <s.icon size={18} />}
                            </div>
                            <span className={`ml-2 text-xs font-bold uppercase tracking-tighter ${step >= s.num ? 'text-white' : 'text-white/20'}`}>
                                {s.label}
                            </span>
                            {s.num < 3 && <div className={`w-12 h-[2px] mx-4 rounded-full ${step > s.num ? 'bg-primary-500' : 'bg-white/5'}`} />}
                        </div>
                    ))}
                </div>
            </div>

            {/* STEP 1: INITIAL SETUP */}
            {step === 1 && (
                <div className="max-w-2xl mx-auto animate-in fade-in slide-in-from-bottom-4 duration-500">
                    <div className="glass-effect p-10 rounded-3xl border border-white/5 shadow-2xl relative overflow-hidden">
                        <div className="absolute top-0 right-0 p-8 opacity-5">
                            <Radar size={150} className="text-white" />
                        </div>
                        <h2 className="text-2xl font-bold text-white mb-6 flex items-center space-x-3">
                            <span className="p-2 rounded-lg bg-primary-500/20 text-primary-400">
                                <Globe size={24} />
                            </span>
                            <span>Define Target Scope</span>
                        </h2>
                        
                        <div className="space-y-6">
                            <div>
                                <label className="block text-[10px] font-black text-dark-text-secondary mb-2 uppercase tracking-widest opacity-60">Base URL / Endpoint</label>
                                <div className="relative group">
                                    <div className="absolute left-5 top-1/2 -translate-y-1/2 text-primary-500 group-focus-within:animate-pulse">
                                        <Server size={20} />
                                    </div>
                                    <input
                                        type="text"
                                        value={targetUrl}
                                        onChange={e => setTargetUrl(e.target.value)}
                                        placeholder="https://testphp.vulnweb.com"
                                        className="w-full pl-14 pr-6 py-5 bg-black/40 border border-white/10 rounded-2xl focus:ring-2 focus:ring-primary-500/50 outline-none transition-all text-white font-mono text-lg placeholder-white/20"
                                    />
                                </div>
                            </div>
                            
                            <div className="p-4 bg-primary-500/5 border border-primary-500/20 rounded-2xl flex items-start space-x-3">
                                <Shield size={18} className="text-primary-400 mt-1 flex-shrink-0" />
                                <p className="text-xs text-dark-text-secondary leading-relaxed">
                                    In Step 1, we will only perform <strong>Discovery & Reconnaissance</strong>. 
                                    NO vulnerability payloads will be sent until you approve the targets in the next step.
                                </p>
                            </div>

                            {/* 🔒 AUTHENTICATION SETTINGS */}
                            <div className={`mt-6 p-6 rounded-2xl border transition-all ${authConfig.enabled ? 'bg-primary-500/5 border-primary-500/20' : 'bg-white/5 border-white/5 opacity-60'}`}>
                                <div className="flex items-center justify-between mb-4">
                                    <div className="flex items-center space-x-3">
                                        <div className={`p-2 rounded-lg ${authConfig.enabled ? 'bg-primary-500/20 text-primary-400' : 'bg-white/10 text-white/40'}`}>
                                            <Lock size={18} />
                                        </div>
                                        <div>
                                            <h3 className="text-sm font-bold text-white uppercase tracking-tight">Authentication Settings</h3>
                                            <p className="text-[10px] text-dark-text-secondary">Perform an authenticated scan</p>
                                        </div>
                                    </div>
                                    <button 
                                        onClick={() => setAuthConfig({...authConfig, enabled: !authConfig.enabled})}
                                        className={`px-3 py-1 rounded-full text-[10px] font-black transition-all ${authConfig.enabled ? 'bg-primary-500 text-white' : 'bg-white/10 text-white/40'}`}
                                    >
                                        {authConfig.enabled ? 'ENABLED' : 'DISABLED'}
                                    </button>
                                </div>

                                {authConfig.enabled && (
                                    <div className="space-y-4 animate-in fade-in slide-in-from-top-2 duration-300">
                                        <div>
                                            <label className="block text-[9px] font-bold text-primary-400 uppercase mb-1">Login Endpoint URL</label>
                                            <input 
                                                type="text" 
                                                placeholder="https://target.com/api/login"
                                                value={authConfig.login_url}
                                                onChange={e => setAuthConfig({...authConfig, login_url: e.target.value})}
                                                className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl focus:border-primary-500/50 outline-none transition-all text-xs font-mono text-white"
                                            />
                                        </div>
                                        <div className="grid grid-cols-2 gap-4">
                                            <div>
                                                <label className="block text-[9px] font-bold text-dark-text-secondary uppercase mb-1">Username / Email</label>
                                                <input 
                                                    type="text" 
                                                    placeholder="admin@target.com"
                                                    value={authConfig.username}
                                                    onChange={e => setAuthConfig({...authConfig, username: e.target.value})}
                                                    className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl focus:border-primary-500/50 outline-none transition-all text-xs font-mono text-white"
                                                />
                                            </div>
                                            <div>
                                                <label className="block text-[9px] font-bold text-dark-text-secondary uppercase mb-1">Password</label>
                                                <input 
                                                    type="password" 
                                                    placeholder="••••••••"
                                                    value={authConfig.password}
                                                    onChange={e => setAuthConfig({...authConfig, password: e.target.value})}
                                                    className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl focus:border-primary-500/50 outline-none transition-all text-xs font-mono text-white"
                                                />
                                            </div>
                                        </div>
                                        <div className="grid grid-cols-2 gap-4 border-t border-white/5 pt-4">
                                            <div>
                                                <label className="block text-[9px] font-bold text-dark-text-secondary uppercase mb-1">Username Field Key</label>
                                                <input 
                                                    type="text" 
                                                    value={authConfig.username_field}
                                                    onChange={e => setAuthConfig({...authConfig, username_field: e.target.value})}
                                                    className="w-full px-4 py-2 bg-black/40 border border-white/5 rounded-lg focus:border-primary-500/50 outline-none transition-all text-[10px] font-mono text-white"
                                                />
                                            </div>
                                            <div>
                                                <label className="block text-[9px] font-bold text-dark-text-secondary uppercase mb-1">Password Field Key</label>
                                                <input 
                                                    type="text" 
                                                    value={authConfig.password_field}
                                                    onChange={e => setAuthConfig({...authConfig, password_field: e.target.value})}
                                                    className="w-full px-4 py-2 bg-black/40 border border-white/5 rounded-lg focus:border-primary-500/50 outline-none transition-all text-[10px] font-mono text-white"
                                                />
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>

                            <button
                                onClick={startDiscovery}
                                disabled={!targetUrl || loading || (authConfig.enabled && !authConfig.login_url)}
                                className="w-full mt-6 py-5 bg-gradient-to-r from-primary-600 to-accent-600 hover:from-primary-500 hover:to-accent-500 text-white font-black rounded-2xl shadow-xl shadow-primary-500/25 transform hover:scale-[1.02] active:scale-95 transition-all flex items-center justify-center space-x-3 disabled:opacity-50"
                            >
                                {loading ? <Loader2 className="animate-spin" /> : <Radar size={20} />}
                                <span className="uppercase tracking-widest">Next: Start Discovery</span>
                                <ArrowRight size={20} />
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* STEP 2: RECON & TARGET SELECTION */}
            {step === 2 && (
                <div className="animate-in fade-in zoom-in-95 duration-500">
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                        {/* Status Panel */}
                        <div className="lg:col-span-1 space-y-6">
                            <div className="glass-effect p-6 rounded-2xl border border-white/5 space-y-4">
                                <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                                    <Activity className="text-primary-400 animate-pulse" size={20} />
                                    <span>Recon Progress</span>
                                </h3>
                                <div className="space-y-1">
                                    <div className="flex justify-between text-[10px] font-bold text-dark-text-secondary uppercase">
                                        <span>Status</span>
                                        <span className="text-primary-400">{reconStatus === 'ready' ? 'FINISHING' : 'SCANNING'}</span>
                                    </div>
                                    <div className="h-2 bg-white/5 rounded-full overflow-hidden">
                                        <div 
                                            className="h-full bg-gradient-to-r from-primary-500 to-accent-500 transition-all duration-1000 ease-out"
                                            style={{ width: `${Math.max(5, reconProgress)}%` }}
                                        />
                                    </div>
                                </div>
                                <div className="p-3 bg-white/5 rounded-xl text-[10px] text-dark-text-secondary line-clamp-3 italic">
                                    Enumerate subdomains, performing DNS resolution and HTTP/S probing...
                                </div>
                            </div>
                            
                            <div className="glass-effect p-6 rounded-2xl border border-white/5">
                                <h3 className="text-sm font-bold text-white mb-4 uppercase tracking-widest opacity-60">Selection Summary</h3>
                                <div className="space-y-3">
                                    <div className="flex justify-between items-center text-sm">
                                        <span className="text-dark-text-secondary">Targets Selected</span>
                                        <span className="text-primary-400 font-bold">{selectedTargets.length}</span>
                                    </div>
                                    <button
                                        onClick={() => setStep(3)}
                                        disabled={selectedTargets.length === 0}
                                        className="w-full py-4 bg-white/10 hover:bg-white/20 text-white font-bold rounded-xl transition-all flex items-center justify-center space-x-2 disabled:opacity-20"
                                    >
                                        <span>Next: Select Modules</span>
                                        <ArrowRight size={18} />
                                    </button>
                                </div>
                            </div>
                        </div>

                        {/* Results Grid */}
                        <div className="lg:col-span-2">
                            <div className="glass-effect p-8 rounded-3xl border border-white/5 min-h-[400px]">
                                <div className="flex justify-between items-center mb-6">
                                    <h2 className="text-xl font-bold text-white">Select Attack Targets</h2>
                                    <button 
                                        onClick={() => setSelectedTargets(discoveredTargets)}
                                        className="text-[10px] font-bold text-primary-400 hover:text-primary-300 uppercase tracking-widest underline decoration-2 underline-offset-4"
                                    >
                                        Select All
                                    </button>
                                </div>

                                {discoveredTargets.length === 0 ? (
                                    <div className="flex flex-col items-center justify-center h-64 text-center opacity-40">
                                        <Loader2 className="animate-spin mb-4" size={32} />
                                        <p className="text-sm italic">Searching for subdomains and live services...</p>
                                    </div>
                                ) : (
                                    <div className="grid grid-cols-1 gap-3">
                                        {discoveredTargets.map(url => (
                                            <label 
                                                key={url}
                                                className={`
                                                    flex items-center space-x-4 p-4 rounded-2xl border transition-all cursor-pointer bg-dark-surface2
                                                    ${selectedTargets.includes(url) ? 'border-primary-500/50 bg-primary-500/5' : 'border-white/5 hover:border-white/10'}
                                                `}
                                            >
                                                <input
                                                    type="checkbox"
                                                    checked={selectedTargets.includes(url)}
                                                    onChange={e => {
                                                        if (e.target.checked) setSelectedTargets([...selectedTargets, url])
                                                        else setSelectedTargets(selectedTargets.filter(t => t !== url))
                                                    }}
                                                    className="w-5 h-5 rounded border-white/10 bg-black/40 text-primary-500 focus:ring-primary-500/50"
                                                />
                                                <div className="flex-1 overflow-hidden">
                                                    <div className="text-sm font-bold text-white truncate font-mono">{url}</div>
                                                    <div className="text-[10px] text-dark-text-secondary uppercase tracking-widest mt-0.5">Live Discovery</div>
                                                </div>
                                                <div className="px-2 py-1 bg-green-500/10 text-green-400 text-[10px] font-bold rounded uppercase">Active</div>
                                            </label>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* STEP 3: MODULE SELECTION */}
            {step === 3 && (
                <div className="max-w-4xl mx-auto animate-in fade-in slide-in-from-right-4 duration-500">
                    <div className="glass-effect p-10 rounded-3xl border border-white/5">
                        <div className="flex justify-between items-center mb-10">
                            <div>
                                <h2 className="text-2xl font-bold text-white">Select Vulnerability Modules</h2>
                                <p className="text-dark-text-secondary text-sm mt-1">Configure your specialized attack group</p>
                            </div>
                            <div className="text-right">
                                <div className="text-[10px] font-bold text-dark-text-secondary uppercase mb-1">Total Selected</div>
                                <div className="text-3xl font-black text-primary-400">{selectedModules.length}</div>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-10">
                            {MODULE_CATEGORIES.map(cat => (
                                <div key={cat.id} className="p-6 bg-white/5 rounded-2xl border border-white/5 group hover:border-primary-500/20 transition-all">
                                    <div className="flex justify-between items-center mb-4">
                                        <div>
                                            <h3 className="text-lg font-bold text-white tracking-tight">{cat.name}</h3>
                                            <p className="text-[10px] text-dark-text-secondary uppercase tracking-widest">{cat.desc}</p>
                                        </div>
                                        <button 
                                            onClick={() => {
                                                const ids = cat.modules.map(m => m.id)
                                                if (ids.every(id => selectedModules.includes(id))) {
                                                    setSelectedModules(selectedModules.filter(id => !ids.includes(id)))
                                                } else {
                                                    setSelectedModules([...new Set([...selectedModules, ...ids])])
                                                }
                                            }}
                                            className="text-[10px] font-black text-primary-400 uppercase"
                                        >
                                            Toggle All
                                        </button>
                                    </div>
                                    <div className="space-y-2">
                                        {cat.modules.map(m => (
                                            <label key={m.id} className="flex items-center space-x-3 cursor-pointer group">
                                                <input
                                                    type="checkbox"
                                                    checked={selectedModules.includes(m.id)}
                                                    onChange={e => {
                                                        if (e.target.checked) setSelectedModules([...selectedModules, m.id])
                                                        else setSelectedModules(selectedModules.filter(id => id !== m.id))
                                                    }}
                                                    className="w-4 h-4 rounded border-white/10 bg-black/40 text-primary-500 focus:ring-primary-500/50"
                                                />
                                                <span className={`text-sm tracking-tight transition-colors ${selectedModules.includes(m.id) ? 'text-white' : 'text-dark-text-secondary'}`}>
                                                    {m.label}
                                                </span>
                                            </label>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* Custom Payloads */}
                        <div className="mb-10">
                            <h3 className="text-lg font-bold text-white mb-2 flex items-center space-x-2">
                                <Bug size={18} className="text-primary-400" />
                                <span>Custom Payloads (Optional)</span>
                            </h3>
                            <p className="text-[10px] text-dark-text-secondary uppercase tracking-widest mb-4">Inject specific payloads across all selected attack vectors (one per line)</p>
                            <textarea 
                                value={customPayloads}
                                onChange={e => setCustomPayloads(e.target.value)}
                                placeholder="<script>alert('XSS')</script>&#10;admin' OR 1=1--"
                                className="w-full h-32 p-4 bg-black/40 border border-white/5 rounded-2xl focus:ring-2 focus:ring-primary-500/50 outline-none transition-all text-white font-mono text-sm placeholder-white/20"
                            />
                        </div>

                        <div className="flex space-x-4">
                            <button
                                onClick={() => setStep(2)}
                                className="px-8 py-5 bg-white/5 hover:bg-white/10 text-white font-bold rounded-2xl transition-all"
                            >
                                Back
                            </button>
                            <button
                                onClick={launchFullScan}
                                disabled={selectedModules.length === 0 || loading}
                                className="flex-1 py-5 bg-gradient-to-r from-primary-600 to-accent-600 hover:from-primary-500 hover:to-accent-500 text-white font-black rounded-2xl shadow-xl shadow-primary-500/25 transform hover:scale-[1.01] active:scale-95 transition-all flex items-center justify-center space-x-3 disabled:opacity-50"
                            >
                                {loading ? <Loader2 className="animate-spin" /> : <Zap size={22} className="fill-white" />}
                                <span className="uppercase tracking-[0.2em] text-lg">Launch Full Attack Group</span>
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}

export default NewScan
