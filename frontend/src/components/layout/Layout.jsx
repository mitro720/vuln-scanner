import { useState, useEffect } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
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
    LogOut,
    Menu,
    X,
    ChevronLeft,
    ChevronRight,
    Search,
    Bell,
    User
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext'

const SidebarItem = ({ item, collapsed, active }) => {
    const Icon = item.icon
    return (
        <Link
            to={item.path}
            className={`
                flex items-center group relative px-3 py-2.5 my-1 rounded-lg transition-all duration-200
                ${active 
                    ? 'bg-primary-500/10 text-primary-400 shadow-[inset_0_0_12px_rgba(139,92,246,0.1)]' 
                    : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
                }
            `}
        >
            <Icon size={20} className={`${active ? 'text-primary-400' : 'group-hover:text-slate-200'}`} />
            {!collapsed && (
                <span className="ml-3 font-medium text-sm tracking-wide transition-opacity duration-200">
                    {item.label}
                </span>
            )}
            
            {/* Tooltip for collapsed state */}
            {collapsed && (
                <div className="absolute left-full ml-4 px-2 py-1 bg-slate-800 text-white text-xs rounded opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity z-50 whitespace-nowrap border border-slate-700 shadow-xl">
                    {item.label}
                </div>
            )}

            {active && (
                <div className="absolute left-0 w-1 h-6 bg-primary-500 rounded-r-full shadow-[0_0_8px_rgba(139,92,246,0.6)]" />
            )}
        </Link>
    )
}

const Sidebar = ({ collapsed, setCollapsed, mobileOpen, setMobileOpen }) => {
    const location = useLocation()
    const { user } = useAuth()
    const isAdmin = user?.role === 'admin'

    const navItems = [
        { path: '/dashboard', icon: LayoutDashboard, label: 'Overview' },
        { path: '/scan/new', icon: Target, label: 'Scanner' },
        { path: '/attack-surface', icon: Radar, label: 'Attack Surface' },
        { path: '/vulnerabilities', icon: Bug, label: 'Vulnerabilities' },
        { path: '/assets', icon: Globe, label: 'Asset Inventory' },
        { path: '/schedules', icon: Calendar, label: 'Scheduler' },
        { path: '/history', icon: History, label: 'Scan History' },
        { path: '/knowledge-base', icon: BookOpen, label: 'Knowledge Base' },
    ]

    const adminItems = [
        { path: '/admin', icon: ShieldCheck, label: 'Administration' },
        { path: '/settings', icon: Settings, label: 'System Settings' },
    ]

    const isActive = (path) => location.pathname === path

    const sidebarContent = (
        <div className="flex flex-col h-full bg-slate-950 border-r border-white/5 shadow-2xl relative z-50">
            {/* Logo Section */}
            <div className={`flex items-center h-16 px-4 border-b border-white/5 ${collapsed ? 'justify-center' : ''}`}>
                <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-gradient-to-br from-primary-500 to-indigo-600 rounded-lg flex items-center justify-center text-white font-bold text-lg shadow-neon shrink-0">
                        S
                    </div>
                    {!collapsed && (
                        <span className="text-xl font-bold bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent tracking-tight">
                            SecureScan
                        </span>
                    )}
                </div>
            </div>

            {/* Nav Items */}
            <div className="flex-1 overflow-y-auto overflow-x-hidden py-4 px-3 scrollbar-none">
                <div className={`mb-4 ${collapsed ? 'text-center' : ''}`}>
                    {!collapsed && <p className="px-3 text-[10px] font-bold text-slate-500 uppercase tracking-[0.2em] mb-2">Main Menu</p>}
                    {navItems.map(item => (
                        <SidebarItem key={item.path} item={item} collapsed={collapsed} active={isActive(item.path)} />
                    ))}
                </div>

                {isAdmin && (
                    <div className={collapsed ? 'text-center' : ''}>
                        {!collapsed && <p className="px-3 text-[10px] font-bold text-slate-500 uppercase tracking-[0.2em] mb-2 mt-6">Control Panel</p>}
                        {adminItems.map(item => (
                            <SidebarItem key={item.path} item={item} collapsed={collapsed} active={isActive(item.path)} />
                        ))}
                    </div>
                )}
            </div>

            {/* Collapse Toggle (Desktop only) */}
            <button 
                onClick={() => setCollapsed(!collapsed)}
                className="hidden lg:flex items-center justify-center h-10 w-full border-t border-white/5 text-slate-500 hover:text-white hover:bg-slate-900/50 transition-colors"
            >
                {collapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
            </button>
        </div>
    )

    return (
        <>
            {/* Mobile Sidebar Overlay */}
            {mobileOpen && (
                <div 
                    className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[60] lg:hidden"
                    onClick={() => setMobileOpen(false)}
                />
            )}

            {/* Mobile Sidebar Drawer */}
            <div className={`
                fixed inset-y-0 left-0 w-64 z-[70] transition-transform duration-300 lg:hidden
                ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}
            `}>
                {sidebarContent}
            </div>

            {/* Desktop Sidebar */}
            <div className={`
                hidden lg:block h-screen transition-all duration-300 ease-in-out shrink-0
                ${collapsed ? 'w-16' : 'w-64'}
            `}>
                {sidebarContent}
            </div>
        </>
    )
}

const Header = ({ setMobileOpen }) => {
    const { user, logout } = useAuth()
    const navigate = useNavigate()

    const handleLogout = () => {
        logout()
        navigate('/login')
    }

    return (
        <header className="h-16 border-b border-white/5 bg-slate-950/50 backdrop-blur-md sticky top-0 z-40 px-4 lg:px-8 flex items-center justify-between">
            {/* Left: Mobile Toggle & Search */}
            <div className="flex items-center space-x-4">
                <button 
                    onClick={() => setMobileOpen(prev => !prev)}
                    className="lg:hidden p-2 text-slate-400 hover:text-white transition-colors"
                >
                    <Menu size={24} />
                </button>

                <div className="hidden md:flex items-center relative group">
                    <Search size={16} className="absolute left-3 text-slate-500 group-focus-within:text-primary-400 transition-colors" />
                    <input 
                        type="text" 
                        placeholder="Search resources..."
                        className="bg-slate-900/50 border border-white/5 rounded-lg pl-10 pr-4 py-1.5 text-sm text-slate-300 focus:outline-none focus:ring-1 focus:ring-primary-500/50 focus:border-primary-500/50 transition-all w-64"
                    />
                </div>
            </div>

            {/* Right: Actions & User */}
            <div className="flex items-center space-x-3">
                <button className="relative p-2 text-slate-400 hover:text-white hover:bg-slate-800/50 rounded-lg transition-all group">
                    <Bell size={20} />
                    <span className="absolute top-2 right-2 w-2 h-2 bg-primary-500 rounded-full border-2 border-slate-950 shadow-[0_0_8px_rgba(139,92,246,0.6)] animate-pulse" />
                </button>
                
                <div className="h-6 w-px bg-white/5 mx-2" />

                <div className="flex items-center space-x-3 pl-2">
                    <div className="hidden sm:flex flex-col items-end mr-1">
                        <span className="text-sm font-semibold text-slate-200 leading-tight">{user?.username || 'Analyst'}</span>
                        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">{user?.role || 'Operator'}</span>
                    </div>
                    
                    <div className="relative group">
                        <button className="flex items-center">
                            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-slate-800 to-slate-900 border border-white/10 flex items-center justify-center text-slate-300 group-hover:border-primary-500/50 transition-all shadow-inner-glass">
                                <User size={20} />
                            </div>
                        </button>
                        
                        {/* Dropdown would go here */}
                    </div>
                    
                    <button 
                        onClick={handleLogout}
                        className="p-2 text-slate-500 hover:text-red-400 hover:bg-red-500/5 rounded-lg transition-all"
                        title="Logout"
                    >
                        <LogOut size={20} />
                    </button>
                </div>
            </div>
        </header>
    )
}

const Layout = ({ children }) => {
    const [collapsed, setCollapsed] = useState(false)
    const [mobileOpen, setMobileOpen] = useState(false)

    // Handle mobile auto-close on navigation
    const location = useLocation()
    useEffect(() => {
        setMobileOpen(false)
    }, [location])

    return (
        <div className="flex h-screen bg-slate-950 text-slate-200 font-sans overflow-hidden">
            <Sidebar 
                collapsed={collapsed} 
                setCollapsed={setCollapsed}
                mobileOpen={mobileOpen}
                setMobileOpen={setMobileOpen}
            />
            
            <div className="flex-1 flex flex-col min-w-0 overflow-hidden relative">
                {/* Background glow effects */}
                <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-primary-500/5 rounded-full blur-[120px] pointer-events-none" />
                <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-indigo-500/5 rounded-full blur-[120px] pointer-events-none" />

                <Header setMobileOpen={setMobileOpen} />
                
                <main className="flex-1 overflow-y-auto scrollbar-thin scrollbar-thumb-slate-800 scrollbar-track-transparent">
                    <div className="p-4 lg:p-8 max-w-7xl mx-auto">
                        <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
                            {children}
                        </div>
                    </div>
                </main>
            </div>
        </div>
    )
}

export default Layout
