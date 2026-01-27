import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/layout/Layout'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import LiveScan from './pages/LiveScan'
import Results from './pages/Results'
import History from './pages/History'
import Settings from './pages/Settings'
import AIChatBot from './components/common/AIChatBot'
import { AIChatProvider } from './context/AIChatContext'

function App() {
    return (
        <Router>
            <AIChatProvider>
                <Layout>
                    <Routes>
                        <Route path="/" element={<Navigate to="/dashboard" replace />} />
                        <Route path="/dashboard" element={<Dashboard />} />
                        <Route path="/scan/new" element={<NewScan />} />
                        <Route path="/scan/:id" element={<LiveScan />} />
                        <Route path="/results/:id" element={<Results />} />
                        <Route path="/history" element={<History />} />
                        <Route path="/settings" element={<Settings />} />
                    </Routes>
                    <AIChatBot />
                </Layout>
            </AIChatProvider>
        </Router>
    )
}

export default App
