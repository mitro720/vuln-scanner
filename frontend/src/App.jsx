import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import Layout from './components/layout/Layout'
import Login from './pages/Login'
import Signup from './pages/Signup'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import LiveScan from './pages/LiveScan'
import Results from './pages/Results'
import History from './pages/History'
import Settings from './pages/Settings'
import Vulnerabilities from './pages/Vulnerabilities'
import Assets from './pages/Assets'
import Schedules from './pages/Schedules'
import ReportPage from './pages/ReportPage'
import AttackSurface from './pages/AttackSurface'
import VisualSurface from './pages/VisualSurface'
import KnowledgeBase from './pages/KnowledgeBase'
import Admin from './pages/Admin'
import AIChatBot from './components/common/AIChatBot'

const ProtectedRoute = ({ children }) => {
    const { user, loading } = useAuth()
    
    if (loading) return null
    if (!user) return <Navigate to="/login" />
    
    return children
}

const AdminRoute = ({ children }) => {
    const { user, loading } = useAuth()
    
    if (loading) return null
    if (!user || user.role !== 'admin') return <Navigate to="/dashboard" />
    
    return children
}

const AppRoutes = () => {
    return (
        <Routes>
            {/* Public Route */}
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Signup />} />

            {/* Private Routes */}
            <Route path="/*" element={
                <ProtectedRoute>
                    <Layout>
                        <Routes>
                            <Route path="/" element={<Navigate to="/dashboard" replace />} />
                            <Route path="/dashboard" element={<Dashboard />} />
                            <Route path="/scan/new" element={<NewScan />} />
                            <Route path="/scan/:id" element={<LiveScan />} />
                            <Route path="/results/:id" element={<Results />} />
                            <Route path="/report/:id" element={<ReportPage />} />
                            <Route path="/history" element={<History />} />
                            <Route path="/settings" element={<Settings />} />
                            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
                            <Route path="/assets" element={<Assets />} />
                            <Route path="/attack-surface" element={<AttackSurface />} />
                            <Route path="/visual-surface/:id" element={<VisualSurface />} />
                            <Route path="/knowledge-base" element={<KnowledgeBase />} />
                            <Route path="/schedules" element={<Schedules />} />
                            <Route path="/admin" element={
                                <AdminRoute>
                                    <Admin />
                                </AdminRoute>
                            } />
                            <Route path="*" element={<Navigate to="/dashboard" />} />
                        </Routes>
                        <AIChatBot />
                    </Layout>
                </ProtectedRoute>
            } />
        </Routes>
    )
}

function App() {
    return (
        <AuthProvider>
            <Router>
                <AppRoutes />
            </Router>
        </AuthProvider>
    )
}

export default App
