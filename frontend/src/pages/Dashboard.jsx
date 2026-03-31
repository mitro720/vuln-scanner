import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
    PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
    AreaChart, Area, XAxis, YAxis, CartesianGrid,
} from 'recharts'
import { 
    Target, AlertTriangle, Activity, Shield, 
    TrendingUp, Bug, Search, Zap, Globe, Layers,
    ArrowRight, Clock, ShieldCheck, ShieldAlert,
    ExternalLink, Server
} from 'lucide-react'
import StatCard from '../components/common/StatCard'
import StatusBadge from '../components/common/StatusBadge'

const Dashboard = () => {
    const [stats, setStats] = useState({
        totalScans: 0,
        criticalFindings: 0,
        activeScans: 0,
        targetsMonitored: 0,
        riskScore: 0,
        totalVulnerabilities: 0,
    })
    const [scans, setScans] = useState([])
    const [trendData, setTrendData] = useState([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchDashboardData = async () => {
            try {
                const token = JSON.parse(localStorage.getItem('user') || '{}')?.token
                const headers = { 
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }

                const [statsRes, scansRes] = await Promise.all([
                    fetch('http://localhost:5000/api/scans/stats', { headers }),
                    fetch('http://localhost:5000/api/scans', { headers })
                ])
                
                if (statsRes.ok && scansRes.ok) {
                    const statsData = await statsRes.json()
                    const scansData = await scansRes.json()
                    const arr = scansData.data || []
                    
                    setScans(arr)
                    setStats(prev => ({ ...prev, ...statsData }))
                    setTrendData(buildTrendData(arr))
                }
            } catch (error) {
                console.error('Dashboard fetch error:', error)
            } finally {
                setLoading(false)
            }
        }

        fetchDashboardData()
        const interval = setInterval(fetchDashboardData, 5000)
        return () => clearInterval(interval)
    }, [])

    const buildTrendData = (arr) => {
        return arr.slice(0, 10).reverse().map((s, i) => ({
            name: `S${i+1}`,
            Critical: s.critical_count || 0,
            High: s.high_count || 0,
            Medium: s.medium_count || 0
        }))
    }

    const formatIP = (url) => {
        try {
            return new URL(url).hostname
        } catch {
            return url
        }
    }

    return (
        <div className="space-y-8 pb-10">
            {/* 1. Page Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                    <h1 className="text-2xl font-black text-slate-100 tracking-tight">System Overview</h1>
                    <p className="text-slate-500 text-sm font-medium">Real-time security posture and scan intelligence.</p>
                </div>
                
                <Link 
                    to="/scan/new" 
                    className="flex items-center justify-center space-x-2 px-5 py-2.5 bg-primary-600 hover:bg-primary-500 text-white rounded-xl font-bold text-sm transition-all shadow-neon hover:shadow-neon-strong active:scale-95 group"
                >
                    <Target size={18} className="group-hover:rotate-12 transition-transform" />
                    <span>Initiate New Scan</span>
                </Link>
            </div>

            {/* 2. Key Metrics Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6">
                <StatCard 
                    title="Risk Posture" 
                    value={`${stats.riskScore}/10`} 
                    icon={ShieldAlert} 
                    color={stats.riskScore > 7 ? 'red' : stats.riskScore > 4 ? 'orange' : 'emerald'}
                    subtitle="Aggregate Score"
                />
                <StatCard 
                    title="Active Scans" 
                    value={stats.activeScans} 
                    icon={Activity} 
                    color="primary" 
                    subtitle="Nodes Running"
                />
                <StatCard 
                    title="Critical Findings" 
                    value={stats.criticalFindings} 
                    icon={ShieldCheck} 
                    color="red" 
                    subtitle="Needs Attention"
                />
                <StatCard 
                    title="Asset Count" 
                    value={stats.targetsMonitored} 
                    icon={Server} 
                    color="blue" 
                    subtitle="Unique Targets"
                />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                {/* 3. Threat Trend Visualization */}
                <div className="lg:col-span-8 bg-slate-900/50 backdrop-blur-md border border-white/5 rounded-3xl p-6 lg:p-8 relative overflow-hidden shadow-inner-glass">
                    <div className="absolute top-0 right-0 w-64 h-64 bg-primary-500/5 rounded-full blur-[100px] pointer-events-none" />
                    
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h3 className="text-lg font-bold text-slate-200">Vulnerability Trends</h3>
                            <p className="text-slate-500 text-xs">Historical detection across the last 10 sessions</p>
                        </div>
                        <div className="flex space-x-2">
                            <div className="flex items-center px-2 py-1 bg-rose-500/10 rounded-md border border-rose-500/20">
                                <div className="w-1.5 h-1.5 rounded-full bg-rose-500 mr-2" />
                                <span className="text-[10px] font-bold text-rose-500 uppercase">Critical</span>
                            </div>
                            <div className="flex items-center px-2 py-1 bg-orange-500/10 rounded-md border border-orange-500/20">
                                <div className="w-1.5 h-1.5 rounded-full bg-orange-500 mr-2" />
                                <span className="text-[10px] font-bold text-orange-500 uppercase">High</span>
                            </div>
                        </div>
                    </div>

                    <div className="h-[320px] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={trendData}>
                                <defs>
                                    <linearGradient id="colorCrit" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.2} />
                                        <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                                    </linearGradient>
                                    <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#f97316" stopOpacity={0.2} />
                                        <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                                <XAxis 
                                    dataKey="name" 
                                    axisLine={false} 
                                    tickLine={false} 
                                    tick={{fill: '#64748b', fontSize: 10, fontWeight: 600}} 
                                />
                                <YAxis 
                                    axisLine={false} 
                                    tickLine={false} 
                                    tick={{fill: '#64748b', fontSize: 10, fontWeight: 600}} 
                                />
                                <Tooltip 
                                    contentStyle={{backgroundColor: '#0f172a', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '12px', boxShadow: '0 10px 15px -3px rgba(0,0,0,0.5)'}}
                                    itemStyle={{fontSize: '12px', fontWeight: 'bold'}}
                                    cursor={{ stroke: '#334155', strokeWidth: 2 }}
                                />
                                <Area 
                                    type="monotone" 
                                    dataKey="Critical" 
                                    stroke="#f43f5e" 
                                    fillOpacity={1} 
                                    fill="url(#colorCrit)" 
                                    strokeWidth={3}
                                    animationDuration={1500}
                                />
                                <Area 
                                    type="monotone" 
                                    dataKey="High" 
                                    stroke="#f97316" 
                                    fillOpacity={1} 
                                    fill="url(#colorHigh)" 
                                    strokeWidth={3}
                                    animationDuration={1500}
                                    animationBegin={300}
                                />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* 4. Attack Vectors & Health */}
                <div className="lg:col-span-4 flex flex-col gap-6">
                    <div className="bg-gradient-to-br from-indigo-600 to-violet-700 rounded-3xl p-6 text-white relative overflow-hidden shadow-2xl group cursor-pointer">
                        <Radar className="absolute bottom-[-20px] right-[-20px] w-32 h-32 opacity-20 group-hover:rotate-12 transition-transform duration-500" />
                        <h3 className="text-xl font-black mb-1">Attack Surface</h3>
                        <p className="text-indigo-100/70 text-xs font-medium mb-6">Continuous discovery engine active.</p>
                        
                        <div className="space-y-3 mb-6">
                            <div className="flex items-center justify-between text-[10px] font-bold uppercase tracking-wider">
                                <span>Domain Discovery</span>
                                <span>88%</span>
                            </div>
                            <div className="h-1.5 w-full bg-white/10 rounded-full overflow-hidden">
                                <div className="h-full bg-white/40 w-[88%] rounded-full shadow-[0_0_8px_white]" />
                            </div>
                        </div>

                        <Link to="/attack-surface" className="flex items-center space-x-2 text-xs font-bold px-4 py-2 bg-white/10 hover:bg-white/20 rounded-lg transition-all w-fit border border-white/10 backdrop-blur-sm">
                            <span>Open Surface Map</span>
                            <ArrowRight size={14} />
                        </Link>
                    </div>

                    <div className="flex-1 bg-slate-900/50 backdrop-blur-md border border-white/5 rounded-3xl p-6 shadow-inner-glass">
                        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-6">Engine Modules</h3>
                        <div className="space-y-4">
                            {[
                                { name: 'SQL Injection', status: 'Online' },
                                { name: 'XSS (Reflected)', status: 'Online' },
                                { name: 'CVE Matcher', status: 'Syncing' },
                                { name: 'API Discovery', status: 'Online' }
                            ].map(mod => (
                                <div key={mod.name} className="flex items-center justify-between group">
                                    <span className="text-xs font-semibold text-slate-300 group-hover:text-slate-100 transition-colors">{mod.name}</span>
                                    <div className="flex items-center">
                                        <div className={`w-1.5 h-1.5 rounded-full mr-2 ${mod.status === 'Online' ? 'bg-emerald-500' : 'bg-amber-500'} animate-pulse`} />
                                        <span className={`text-[10px] font-bold uppercase ${mod.status === 'Online' ? 'text-emerald-500' : 'text-amber-500'}`}>{mod.status}</span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            {/* 5. Scan Operations Table */}
            <div className="bg-slate-900/50 backdrop-blur-md border border-white/5 rounded-3xl overflow-hidden shadow-inner-glass">
                <div className="p-6 border-b border-white/5 flex items-center justify-between bg-white/[0.01]">
                    <div>
                        <h3 className="text-lg font-bold text-slate-200">Recent Operations</h3>
                        <p className="text-slate-500 text-xs">A comprehensive log of all recent scan activities.</p>
                    </div>
                    <Link to="/history" className="text-xs font-bold text-primary-400 hover:text-primary-300 flex items-center space-x-1 group uppercase tracking-widest">
                        <span>Full Log History</span>
                        <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
                    </Link>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead>
                            <tr className="bg-white/[0.02] text-[10px] font-bold text-slate-500 uppercase tracking-[0.15em] border-b border-white/5">
                                <th className="px-6 py-4">Node / Target</th>
                                <th className="px-6 py-4">Status</th>
                                <th className="px-6 py-4">Risk Magnitude</th>
                                <th className="px-6 py-4">Metadata</th>
                                <th className="px-6 py-4 text-right">Action</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5">
                            {scans.slice(0, 8).map((scan) => (
                                <tr key={scan.id} className="group hover:bg-white/[0.02] transition-colors">
                                    <td className="px-6 py-4">
                                        <div className="flex items-center space-x-3">
                                            <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center text-slate-400 group-hover:bg-primary-500/10 group-hover:text-primary-400 transition-colors border border-white/5">
                                                <Globe size={16} />
                                            </div>
                                            <div className="flex flex-col min-w-0">
                                                <span className="text-sm font-bold text-slate-200 truncate max-w-[240px] tracking-tight">{formatIP(scan.target_url)}</span>
                                                <span className="text-[10px] text-slate-500 font-mono tracking-tighter">ID: {scan.id?.substring(0,8)}</span>
                                            </div>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4">
                                        <StatusBadge status={scan.status} />
                                    </td>
                                    <td className="px-6 py-4">
                                        <div className="flex items-center space-x-3">
                                            <div className="flex -space-x-1">
                                                {scan.critical_count > 0 && <div className="w-2 h-2 rounded-full bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.4)]" />}
                                                {scan.high_count > 0 && <div className="w-2 h-2 rounded-full bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.4)] ml-0.5" />}
                                                {scan.findings_count > 0 && <div className="w-2 h-2 rounded-full bg-primary-500 shadow-[0_0_8px_rgba(139,92,246,0.4)] ml-0.5" />}
                                            </div>
                                            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-tight">
                                                {scan.findings_count || 0} Vulnerabilities
                                            </span>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4">
                                        <div className="flex items-center text-slate-500 space-x-3">
                                            <div className="flex items-center text-[10px] font-bold uppercase">
                                                <Clock size={12} className="mr-1.5" />
                                                {new Date(scan.created_at).toLocaleDateString()}
                                            </div>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4 text-right">
                                        <Link 
                                            to={scan.status === 'running' ? `/scan/${scan.id}` : `/results/${scan.id}`} 
                                            className="inline-flex items-center space-x-1 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-[10px] font-black uppercase transition-all border border-white/5"
                                        >
                                            <span>Inspect</span>
                                            <ExternalLink size={12} />
                                        </Link>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                
                {scans.length === 0 && (
                    <div className="py-20 flex flex-col items-center justify-center text-center px-4">
                        <div className="w-16 h-16 bg-slate-800/50 rounded-2xl flex items-center justify-center mb-4 text-slate-600 border border-white/5">
                            <Activity size={32} />
                        </div>
                        <h4 className="text-slate-300 font-bold tracking-tight">No Operational Data</h4>
                        <p className="text-slate-500 text-xs mt-1 max-w-[240px]">Initialize your first scan to begin global threat discovery.</p>
                    </div>
                )}
            </div>
        </div>
    )
}

const Radar = ({ className }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <circle cx="12" cy="12" r="6" />
        <circle cx="12" cy="12" r="2" />
        <path d="M12 2v20" />
        <path d="M2 12h20" />
    </svg>
)

export default Dashboard
