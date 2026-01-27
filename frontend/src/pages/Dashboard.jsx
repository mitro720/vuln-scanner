import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import StatCard from '../components/common/StatCard'
import StatusBadge from '../components/common/StatusBadge'
import { Target, AlertTriangle, Activity, Shield } from 'lucide-react'

const Dashboard = () => {
    const [stats, setStats] = useState({
        totalScans: 0,
        criticalFindings: 0,
        activeScans: 0,
        targetsMonitored: 0,
    })

    const [scans, setScans] = useState([])
    const [loading, setLoading] = useState(true)

    // Fetch real data on component mount
    useEffect(() => {
        const fetchDashboardData = async () => {
            try {
                // In a real app, these endpoints would return actual DB data
                // For now, if the endpoints don't exist yet, we handle errors gracefully
                const statsRes = await fetch('http://localhost:5000/api/scans/stats')
                if (statsRes.ok) {
                    const statsData = await statsRes.json()
                    setStats(statsData)
                }

                const scansRes = await fetch('http://localhost:5000/api/scans')
                if (scansRes.ok) {
                    const scansData = await scansRes.json()
                    setScans(scansData.data || [])  // Extract the data array
                }
            } catch (error) {
                console.error("Failed to fetch dashboard data:", error)
            } finally {
                setLoading(false)
            }
        }

        fetchDashboardData()

        // Refresh every 10 seconds
        const interval = setInterval(fetchDashboardData, 10000)
        return () => clearInterval(interval)
    }, [])

    return (
        <div className="max-w-7xl mx-auto px-4">
            <h1 className="text-4xl font-bold mb-8 text-gradient">
                Dashboard
            </h1>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                <StatCard
                    title="Total Scans"
                    value={stats.totalScans}
                    trend={{ positive: true, text: 'All time' }}
                    icon={Target}
                    color="purple"
                />
                <StatCard
                    title="Critical Findings"
                    value={stats.criticalFindings}
                    trend={{ positive: false, text: 'Requires attention' }}
                    icon={AlertTriangle}
                    color="red"
                />
                <StatCard
                    title="Active Scans"
                    value={stats.activeScans}
                    icon={Activity}
                    color="blue"
                />
                <StatCard
                    title="Targets Monitored"
                    value={stats.targetsMonitored}
                    icon={Shield}
                    color="green"
                />
            </div>

            {/* Recent Scans Table */}
            <div className="bg-white rounded-xl shadow-lg p-6 mb-8">
                <div className="flex items-center justify-between mb-6">
                    <h3 className="text-xl font-semibold text-gray-800">Recent Scans</h3>
                    <Link to="/history" className="text-purple-600 hover:text-purple-700 font-medium text-sm">
                        View All
                    </Link>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead>
                            <tr className="text-left text-sm text-gray-500 border-b">
                                <th className="pb-3 pl-4">Target URL</th>
                                <th className="pb-3">Status</th>
                                <th className="pb-3">Vulnerabilities</th>
                                <th className="pb-3">Date</th>
                                <th className="pb-3 pr-4">Action</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y">
                            {loading ? (
                                <tr><td colSpan="5" className="text-center py-4">Loading scans...</td></tr>
                            ) : scans.length === 0 ? (
                                <tr><td colSpan="5" className="text-center py-4 text-gray-500">No scans found. Start a new one!</td></tr>
                            ) : (
                                scans.slice(0, 5).map((scan) => (
                                    <tr key={scan.id} className="hover:bg-gray-50 transition-colors">
                                        <td className="py-4 pl-4 font-medium text-gray-800">{scan.target_url}</td>
                                        <td className="py-4">
                                            <StatusBadge status={scan.status} />
                                        </td>
                                        <td className="py-4">
                                            <div className="flex items-center space-x-2">
                                                <span className="font-semibold text-gray-700">{scan.findings_count || 0}</span>
                                                {scan.critical_count > 0 && (
                                                    <span className="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded-full font-bold">
                                                        {scan.critical_count} Crit
                                                    </span>
                                                )}
                                            </div>
                                        </td>
                                        <td className="py-4 text-sm text-gray-500">
                                            {new Date(scan.created_at).toLocaleDateString()}
                                        </td>
                                        <td className="py-4 pr-4">
                                            <Link
                                                to={`/results/${scan.id}`}
                                                className="text-purple-600 hover:text-purple-700 font-medium text-sm"
                                            >
                                                View Report
                                            </Link>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    )
}

export default Dashboard
