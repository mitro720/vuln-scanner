import { createContext, useState, useEffect, useContext } from 'react'
import authService from '../services/authService'

const AuthContext = createContext()

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const authData = authService.getCurrentUser()
        if (authData && authData.user) {
            setUser(authData.user)
        }
        setLoading(false)
    }, [])

    const login = async (username, password) => {
        const data = await authService.login(username, password)
        if (data && data.user) {
            setUser(data.user)
        }
        return data
    }

    const register = async (username, password) => {
        return await authService.register(username, password)
    }

    const logout = () => {
        authService.logout()
        setUser(null)
    }

    return (
        <AuthContext.Provider value={{ user, loading, login, register, logout }}>
            {!loading && children}
        </AuthContext.Provider>
    )
}

export const useAuth = () => useContext(AuthContext)
