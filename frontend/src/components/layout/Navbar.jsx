import { Link, useLocation } from 'react-router-dom'
import {
    LayoutDashboard,
    Target,
    Activity,
    FileText,
    History,
    Settings,
    Book
} from 'lucide-react'

const Navbar = () => {
    const location = useLocation()

    const navItems = [
        { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
        { path: '/scan/new', icon: Target, label: 'New Scan' },
        { path: '/history', icon: History, label: 'History' },
        { path: '/knowledge', icon: Book, label: 'Knowledge' },
        { path: '/settings', icon: Settings, label: 'Settings' },
    ]

    const isActive = (path) => {
        if (path === '/') return location.pathname === '/'
        return location.pathname.startsWith(path)
    }

    return (
        <nav className="bg-white shadow-lg sticky top-0 z-50">
            <div className="max-w-7xl mx-auto px-4">
                <div className="flex justify-between items-center h-16">
                    {/* Logo */}
                    <Link to="/" className="flex items-center space-x-3">
                        <div className="w-10 h-10 gradient-bg rounded-lg flex items-center justify-center text-white font-bold text-xl shadow-lg">
                            S
                        </div>
                        <span className="text-2xl font-bold text-gradient">
                            SecureScan
                        </span>
                    </Link>

                    {/* Navigation Items */}
                    <div className="flex space-x-1">
                        {navItems.map((item) => {
                            const Icon = item.icon
                            return (
                                <Link
                                    key={item.path}
                                    to={item.path}
                                    className={`
                    flex items-center space-x-2 px-4 py-2 rounded-lg transition-all duration-200
                    ${isActive(item.path)
                                            ? 'gradient-bg text-white shadow-lg'
                                            : 'text-gray-600 hover:bg-gray-100'
                                        }
                  `}
                                >
                                    <Icon size={18} />
                                    <span className="font-medium">{item.label}</span>
                                </Link>
                            )
                        })}
                    </div>

                    {/* User Menu */}
                    <div className="flex items-center space-x-4">
                        <button className="p-2 rounded-lg hover:bg-gray-100 transition-colors">
                            <Activity size={20} className="text-gray-600" />
                        </button>
                        <div className="w-8 h-8 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full"></div>
                    </div>
                </div>
            </div>
        </nav>
    )
}

export default Navbar
