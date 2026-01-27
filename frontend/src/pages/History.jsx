import { useState } from 'react'
import { Link } from 'react-router-dom'
import SeverityBadge from '../components/common/SeverityBadge'
import { CheckCircle, Loader, XCircle, Eye } from 'lucide-react'

const History = () => {
    const [scans] = useState([
        {
            id: 1,
            target: 'example.com',
            status: 'completed',
            date: '2026-01-26',
            findings: 12,
            critical: 2,
            high: 4,
            medium: 5,
            low: 1,
        },
        {
            id: 2,
            target: 'test.com',
            status: 'running',
            date: '2026-01-26',
            findings: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        },
        {
            id: 3,
            target: 'api.dev.io',
            status: 'completed',
            date: '2026-01-25',
            findings: 8,
            critical: 1,
            high: 2,
            medium: 3,
            low: 2,
        },
        {
            id: 4,
            target: 'staging.app.com',
            status: 'failed',
            date: '2026-01-25',
            findings: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        },
    ])

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

            <div className="bg-white rounded-xl shadow-lg overflow-hidden">
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
                            <tr key={scan.id} className="hover:bg-gray-50 transition-colors">
                                <td className="px-6 py-4 text-sm text-gray-600">{scan.date}</td>
                                <td className="px-6 py-4">
                                    <div className="font-semibold text-gray-800">{scan.target}</div>
                                </td>
                                <td className="px-6 py-4">{getStatusBadge(scan.status)}</td>
                                <td className="px-6 py-4 text-sm font-semibold text-gray-800">
                                    {scan.findings}
                                </td>
                                <td className="px-6 py-4">
                                    <div className="flex flex-wrap gap-1">
                                        {scan.critical > 0 && (
                                            <span className="px-2 py-1 bg-red-100 text-red-800 rounded text-xs font-semibold">
                                                C:{scan.critical}
                                            </span>
                                        )}
                                        {scan.high > 0 && (
                                            <span className="px-2 py-1 bg-orange-100 text-orange-800 rounded text-xs font-semibold">
                                                H:{scan.high}
                                            </span>
                                        )}
                                        {scan.medium > 0 && (
                                            <span className="px-2 py-1 bg-yellow-100 text-yellow-800 rounded text-xs font-semibold">
                                                M:{scan.medium}
                                            </span>
                                        )}
                                        {scan.low > 0 && (
                                            <span className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs font-semibold">
                                                L:{scan.low}
                                            </span>
                                        )}
                                    </div>
                                </td>
                                <td className="px-6 py-4">
                                    {scan.status === 'completed' ? (
                                        <Link
                                            to={`/results/${scan.id}`}
                                            className="flex items-center space-x-1 text-purple-600 hover:text-purple-800 font-semibold text-sm transition-colors"
                                        >
                                            <Eye size={16} />
                                            <span>View Report</span>
                                        </Link>
                                    ) : scan.status === 'running' ? (
                                        <Link
                                            to={`/scan/${scan.id}`}
                                            className="flex items-center space-x-1 text-blue-600 hover:text-blue-800 font-semibold text-sm transition-colors"
                                        >
                                            <Activity size={16} />
                                            <span>View Progress</span>
                                        </Link>
                                    ) : (
                                        <span className="text-gray-400 text-sm">No report</span>
                                    )}
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
