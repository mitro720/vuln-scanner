import {
    LayoutDashboard,
    Target,
    Activity,
    Bug,
    Globe,
    History,
    Settings,
    Calendar,
    Radar,
    BookOpen,
    ShieldCheck,
    LogOut
} from 'lucide-react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'

const Navbar = () => {
    const location = useLocation()
    const navigate = useNavigate()
    const { user, logout } = useAuth()
    const isAdmin = user?.role === 'admin'

    const handleLogout = () => {
        logout()
        navigate('/login')
    }

    const navItems = [
        { path: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
        { path: '/scan/new', icon: Target, label: 'New Scan' },
        { path: '/attack-surface', icon: Radar, label: 'Attack Surface' },
        { path: '/vulnerabilities', icon: Bug, label: 'Vulnerabilities' },
        { path: '/assets', icon: Globe, label: 'Assets' },
        { path: '/schedules', icon: Calendar, label: 'Schedules' },
        { path: '/history', icon: History, label: 'History' },
        { path: '/admin', icon: ShieldCheck, label: 'Admin', adminOnly: true },
        { path: '/knowledge-base', icon: BookOpen, label: 'Knowledge Base' },
        { path: '/settings', icon: Settings, label: 'Settings' },
    ]

    const filteredItems = navItems.filter(item => !item.adminOnly || isAdmin)

    const isActive = (path) => {
        if (path === '/') return location.pathname === '/'
        return location.pathname.startsWith(path)
    }

    return (
        <nav className="glass-effect sticky top-0 z-50 border-b border-white/5">
            <div className="max-w-[1600px] mx-auto px-4 lg:px-8">
                <div className="flex justify-between items-center h-16">
                    {/* Logo */}
                    <Link to="/" className="flex items-center space-x-3 group">
                        <div className="w-10 h-10 gradient-bg rounded-lg flex items-center justify-center text-white font-bold text-xl shadow-lg ring-1 ring-white/20 group-hover:shadow-primary-500/40 transition-shadow">
                            S
                        </div>
                        <span className="text-2xl font-bold text-gradient tracking-tight">
                            SecureScan
                        </span>
                    </Link>

                    {/* Navigation Items */}
                    <div className="flex space-x-1 lg:space-x-2">
                        {filteredItems.map((item) => {
                            const Icon = item.icon
                            const active = isActive(item.path)
                            return (
                                <Link
                                    key={item.path}
                                    to={item.path}
                                    className={`
                                        flex items-center space-x-2 px-3 lg:px-4 py-2 rounded-xl transition-all duration-300
                                        ${active
                                            ? 'gradient-bg text-white shadow-lg neon-border'
                                            : 'text-dark-text-secondary hover:bg-dark-surface2 hover:text-white'
                                        }
                                    `}
                                >
                                    <Icon size={18} className={active ? "opacity-100" : "opacity-80"} />
                                    <span className="font-medium text-sm lg:text-base hidden sm:block">{item.label}</span>
                                </Link>
                            )
                        })}
                    </div>

                    {/* User Menu */}
                    <div className="flex items-center space-x-4">
                        <button className="p-2 rounded-xl hover:bg-dark-surface2 transition-colors group">
                            <Activity size={20} className="text-dark-text-secondary group-hover:text-primary-400 transition-colors" />
                        </button>
                        <button onClick={handleLogout} className="p-2 rounded-xl hover:bg-red-500/10 transition-colors group" title="Logout">
                            <LogOut size={20} className="text-dark-text-secondary group-hover:text-red-400 transition-colors" />
                        </button>
                        <div className="w-8 h-8 rounded-full bg-gradient-accent ring-2 ring-primary-500/50 shadow-lg cursor-pointer"></div>
                    </div>
                </div>
            </div>
        </nav>
    )
}

export default Navbar
