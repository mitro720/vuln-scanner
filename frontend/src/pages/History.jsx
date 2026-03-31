import { useState } from 'react'
import { Link } from 'react-router-dom'
import SeverityBadge from '../components/common/SeverityBadge'
import { CheckCircle, Loader, XCircle, Eye, Activity, Square, Trash2 } from 'lucide-react'

const API = 'http://localhost:5000/api'

const History = () => {
    const [scans, setScans] = useState([])
    const [loading, setLoading] = useState(true)

    const fetchScans = async () => {
        try {
            const token = JSON.parse(localStorage.getItem('user') || '{}')?.token
            const resp = await fetch('http://localhost:5000/api/scans', {
                headers: { 'Authorization': `Bearer ${token}` }
            })
            if (resp.ok) {
                const data = await resp.json()
                setScans(data.data || [])
            }
        } catch (e) {
            console.error(e)
        } finally {
            setLoading(false)
        }
    }

    useState(() => {
        fetchScans()
        const interval = setInterval(fetchScans, 10000)
        return () => clearInterval(interval)
    }, [])

    const handleStop = async (id) => {
        if (!window.confirm("Stop this scan?")) return
        try {
            const token = JSON.parse(localStorage.getItem('user') || '{}')?.token
            await fetch(`${API}/scans/${id}/stop`, { 
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            })
            fetchScans()
        } catch (e) {
            console.error(e)
        }
    }

    const handleDelete = async (id) => {
        if (!window.confirm("🗑️ Are you sure you want to PERMANENTLY DELETE this scan and all its findings?")) return
        try {
            const token = JSON.parse(localStorage.getItem('user') || '{}')?.token
            const resp = await fetch(`${API}/scans/${id}`, { 
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
            })
            if (resp.ok) {
                setScans(prev => prev.filter(s => s.id !== id))
            }
        } catch (e) {
            console.error(e)
        }
    }

    const getStatusIcon = (status) => {
        switch (status) {
            case 'completed':
                return <CheckCircle className="text-green-500" size={20} />
            case 'running':
                return <Loader className="text-blue-500 animate-spin" size={20} />
            case 'failed':
                return <XCircle className="text-red-500" size={20} />
            default:
                return null
        }
    }

    const getStatusBadge = (status) => {
        const classes = {
            completed: 'bg-green-100 text-green-800',
            running: 'bg-blue-100 text-blue-800',
            failed: 'bg-red-100 text-red-800',
        }

        return (
            <span className={`px-3 py-1 rounded-full text-xs font-semibold flex items-center space-x-1 ${classes[status]}`}>
                {getStatusIcon(status)}
                <span className="ml-1">{status.toUpperCase()}</span>
            </span>
        )
    }

    return (
        <div className="max-w-7xl mx-auto px-4">
            <h1 className="text-4xl font-bold mb-8 text-gradient">Scan History</h1>

            <div className="bg-gray-900 rounded-xl shadow-lg overflow-hidden">
                <table className="w-full">
                    <thead className="bg-gray-50 border-b border-gray-200">
                        <tr>
                            <th className="px-6 py-4 text-left text-sm font-semibold text-gray-700">Date</th>
                            <th className="px-6 py-4 text-left text-sm font-semibold text-gray-700">Target</th>
                            <th className="px-6 py-4 text-left text-sm font-semibold text-gray-700">Status</th>
                            <th className="px-6 py-4 text-left text-sm font-semibold text-gray-700">Findings</th>
                            <th className="px-6 py-4 text-left text-sm font-semibold text-gray-700">Severity</th>
                            <th className="px-6 py-4 text-left text-sm font-semibold text-gray-700">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-200">
                        {scans.map((scan) => (
                            <tr key={scan.id} className="hover:bg-gray-800 transition-colors">
                                <td className="px-6 py-4 text-sm text-gray-300">
                                    {new Date(scan.created_at).toLocaleDateString()}
                                </td>
                                <td className="px-6 py-4">
                                    <div className="font-semibold text-white truncate max-w-md">{scan.target_url}</div>
                                </td>
                                <td className="px-6 py-4">{getStatusBadge(scan.status)}</td>
                                <td className="px-6 py-4 text-sm font-semibold text-white">
                                    {scan.findings_count || 0}
                                </td>
                                <td className="px-6 py-4">
                                    <div className="flex flex-wrap gap-1">
                                        {(scan.critical_count > 0) && (
                                            <span className="px-2 py-1 bg-red-900/40 text-red-400 rounded text-[10px] font-bold">
                                                C:{scan.critical_count}
                                            </span>
                                        )}
                                        {(scan.high_count > 0) && (
                                            <span className="px-2 py-1 bg-orange-900/40 text-orange-400 rounded text-[10px] font-bold">
                                                H:{scan.high_count}
                                            </span>
                                        )}
                                        {(scan.medium_count > 0) && (
                                            <span className="px-2 py-1 bg-yellow-900/40 text-yellow-400 rounded text-[10px] font-bold">
                                                M:{scan.medium_count}
                                            </span>
                                        )}
                                    </div>
                                </td>
                                <td className="px-6 py-4">
                                    <div className="flex items-center space-x-4">
                                        <Link
                                            to={scan.status === 'completed' ? `/results/${scan.id}` : `/scan/${scan.id}`}
                                            className="flex items-center space-x-1 text-purple-400 hover:text-purple-300 font-semibold text-sm transition-colors"
                                        >
                                            <Eye size={16} />
                                            <span>{scan.status === 'completed' ? 'View Report' : 'Live View'}</span>
                                        </Link>
                                        {(scan.status === 'running' || scan.status === 'pending') && (
                                            <button 
                                                onClick={() => handleStop(scan.id)}
                                                className="text-red-500 hover:text-red-400 p-2 hover:bg-red-500/10 rounded-lg transition-all"
                                                title="Stop Scan"
                                            >
                                                <Square size={16} fill="currentColor" />
                                            </button>
                                        )}
                                        <button 
                                            onClick={() => handleDelete(scan.id)}
                                            className="text-gray-500 hover:text-red-500 p-2 hover:bg-red-500/10 rounded-lg transition-all"
                                            title="Delete Scan"
                                        >
                                            <Trash2 size={16} />
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    )
}

export default History
